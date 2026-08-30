import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional

from aurascan.core.ai_provider import (
    AI_BASE_URL_ENV,
    AI_ENABLED_ENV,
    AI_MODEL_ENV,
    AI_PROVIDER_ENV,
    AIProviderError,
    PROVIDERS,
    call_ai_provider,
    connectivity_prompt,
    get_provider_spec,
    normalize_local_base_url,
    provider_choices,
    resolve_ai_config,
    safe_provider_error_detail,
)
from aurascan.core.agent import (
    AGENT_ACCESS_ENV,
    AGENT_ACCESS_VALUES,
    AGENT_APPROVAL_ENV,
    AGENT_APPROVAL_VALUES,
    AGENT_DEFAULT_SESSION_MINUTES,
    AGENT_MAX_SESSION_MINUTES,
    AGENT_OUTPUT_SHARING_ENV,
    AGENT_OUTPUT_VALUES,
    AGENT_ROOT_POLICY_PATH,
    AGENT_SESSION_TIMEOUT_ENV,
    agent_doctor_status,
    configure_agent_root_policy,
    effective_agent_approval,
    read_agent_root_policy,
    resolve_agent_config,
)
from aurascan.core.config import file_mode, read_env_file, user_env_path, write_user_env
from aurascan.core.config_drift import (
    CONFIG_DRIFT_AI_DIFFS_ENV,
    CONFIG_DRIFT_AI_DIFFS_VALUES,
    CONFIG_DRIFT_ENABLED_ENV,
    resolve_config_drift_config,
)
from aurascan.core.compatibility import (
    detect_desktop_session,
    detect_distro,
    detect_package_manager_capabilities,
)
from aurascan.core.followup import followup_doctor_status
from aurascan.core.hardware_health import hardware_health_doctor_status
from aurascan.core.kernel_module_autopilot import (
    KERNEL_MODULE_AUTOPILOT_ENV,
    detect_module_families,
    is_kernel_base_package,
)
from aurascan.core.incidents import (
    INCIDENT_AI_ENABLED_ENV,
    INCIDENT_AI_EVIDENCE_ENV,
    INCIDENT_AI_EVIDENCE_VALUES,
    INCIDENT_BACKGROUND_AI_ENV,
    INCIDENT_MONITOR_ENABLED_ENV,
    INCIDENT_MAINTENANCE_SERVICE,
    INCIDENT_MAINTENANCE_TIMER,
    INCIDENT_MONITOR_SERVICE,
    INCIDENT_SYSTEM_ROOT,
    incident_monitor_status,
    load_maintenance_status,
    maintenance_paths,
    resolve_incident_config,
    run_bounded_command,
    set_incident_monitor_enabled,
    user_incident_root,
)
from aurascan.core.incident_automation import (
    INCIDENT_AUTO_REPAIR_POLICY_PATH,
    INCIDENT_AUTO_REPAIR_VALUES,
    INCIDENT_SAFE_AUTOPILOT_SERVICE,
    INCIDENT_USER_UNIT_ROOT,
    background_result_path,
    background_state_path,
    background_unit_status,
    configure_auto_repair_policy,
    load_private_json,
    read_auto_repair_policy,
    safe_automation_paths,
    set_background_ai_enabled,
)
from aurascan.core.instruction_cli import (
    INSTRUCTION_AI_ENABLED_ENV,
    INSTRUCTION_ASSISTANT_SERVICE,
    INSTRUCTION_ASSISTANT_TIMER,
    INSTRUCTION_MONITOR_ENABLED_ENV,
    INSTRUCTION_MONITOR_SERVICE,
    INSTRUCTION_MONITOR_TIMER,
    INSTRUCTION_SCAN_MODE_ENV,
    INSTRUCTION_SCAN_MODES,
    INSTRUCTION_USER_UNIT_ROOT,
    _capture_user_timer_state,
    _restore_user_timer_state,
    instruction_guard_unit_status,
    resolve_instruction_guard_preferences,
    set_instruction_ai_enabled,
    set_instruction_monitor_enabled,
)
from aurascan.core.recovery import (
    RECOVERY_AI_ENABLED_ENV,
    RECOVERY_AUTO_REFRESH_ENV,
    RECOVERY_WIFI_PROFILES_ENV,
    RECOVERY_WIFI_PROFILE_VALUES,
    read_recovery_policy,
    resolve_recovery_config,
)
from aurascan.core.recovery_cli import recovery_status
from aurascan.core.security_audit import bundled_campaign_doctor_status
from aurascan.core.upgrade_preflight import (
    UPGRADE_AUR_HELPERS,
    UPGRADE_PREFLIGHT_AI_ENV,
    UPGRADE_PREFLIGHT_AUR_HELPER_ENV,
    UPGRADE_PREFLIGHT_ENABLED_ENV,
    resolve_upgrade_config,
)
from aurascan.core.updater_tray import (
    UPDATER_AUTOSTART_ENV,
    UPDATER_TERMINAL_ENV,
    UPDATER_TRAY_ENABLED_ENV,
    build_updater_status,
    install_updater_autostart,
    remove_updater_autostart,
    resolve_updater_config,
    updater_desktop_paths,
)

LOCAL_HOOK_PATH = Path("/etc/pacman.d/hooks/aurascan.hook")
PACKAGED_HOOK_PATH = Path("/usr/share/libalpm/hooks/aurascan.hook")
INSTALLED_AURASCAN = Path("/usr/bin/aurascan")


def resolve_hook_template_path(
    module_path: Path = Path(__file__),
    packaged_hook_path: Path = PACKAGED_HOOK_PATH,
) -> Path:
    source_template = module_path.resolve().parents[1] / "packaging" / "arch" / "aurascan.hook"
    return source_template if source_template.is_file() else packaged_hook_path


TEMPLATE_HOOK_PATH = resolve_hook_template_path()


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
    parser.add_argument("--base-url", help="loopback OpenAI-compatible base URL for a local AI provider")
    ai = parser.add_mutually_exclusive_group()
    ai.add_argument("--enable-ai", action="store_true", help="enable configured AI analysis")
    ai.add_argument("--disable-ai", action="store_true", help="write config that keeps AI analysis disabled")
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
    kernel_module_autopilot = parser.add_mutually_exclusive_group()
    kernel_module_autopilot.add_argument("--enable-kernel-module-autopilot", action="store_true", help="enable kernel/module autopilot during upgrades")
    kernel_module_autopilot.add_argument("--disable-kernel-module-autopilot", action="store_true", help="disable kernel/module autopilot during upgrades")
    incident_monitor = parser.add_mutually_exclusive_group()
    incident_monitor.add_argument("--enable-incident-monitor", action="store_true", help="enable read-only previous-boot and weekly incident detection")
    incident_monitor.add_argument("--disable-incident-monitor", action="store_true", help="disable previous-boot and weekly incident detection")
    incident_ai = parser.add_mutually_exclusive_group()
    incident_ai.add_argument("--enable-incident-ai", action="store_true", help="enable AI explanation for user-opened incident scans")
    incident_ai.add_argument("--disable-incident-ai", action="store_true", help="disable AI explanation for incident scans")
    parser.add_argument("--incident-ai-evidence", choices=sorted(INCIDENT_AI_EVIDENCE_VALUES), help="evidence policy for user-opened incident AI reviews")
    incident_background_ai = parser.add_mutually_exclusive_group()
    incident_background_ai.add_argument("--enable-incident-background-ai", action="store_true", help="enable logged-in background incident AI analysis")
    incident_background_ai.add_argument("--disable-incident-background-ai", action="store_true", help="disable logged-in background incident AI analysis")
    parser.add_argument("--incident-auto-repair", choices=sorted(INCIDENT_AUTO_REPAIR_VALUES), help="system-wide deterministic incident repair policy")
    instruction_monitor = parser.add_mutually_exclusive_group()
    instruction_monitor.add_argument("--enable-instruction-monitor", action="store_true", help="enable the unprivileged Agent Instruction Guard monitor")
    instruction_monitor.add_argument("--disable-instruction-monitor", action="store_true", help="disable the Agent Instruction Guard monitor")
    instruction_ai = parser.add_mutually_exclusive_group()
    instruction_ai.add_argument("--enable-instruction-ai", action="store_true", help="enable separately scheduled raise-only AI analysis for agent files")
    instruction_ai.add_argument("--disable-instruction-ai", action="store_true", help="disable Agent Instruction Guard AI analysis")
    parser.add_argument("--instruction-scan-mode", choices=sorted(INSTRUCTION_SCAN_MODES), help="agent control files only, or optional content-only analysis of all Markdown")
    parser.add_argument("--agent-access", choices=AGENT_ACCESS_VALUES, help="foreground Policy-Gated Repair Agent access profile")
    parser.add_argument(
        "--agent-approval",
        choices=AGENT_APPROVAL_VALUES,
        help="policy-gated command approval mode (legacy broader values are enforced as each-command)",
    )
    parser.add_argument("--agent-output-sharing", choices=AGENT_OUTPUT_VALUES, help="foreground agent terminal-output sharing policy")
    parser.add_argument("--agent-session-timeout", type=int, metavar="MINUTES", help="foreground agent session duration")
    agent_root = parser.add_mutually_exclusive_group()
    agent_root.add_argument("--allow-agent-root", action="store_true", help="allow separately consented policy-gated root repair sessions")
    agent_root.add_argument("--deny-agent-root", action="store_true", help="disable policy-gated root repair sessions system-wide")
    parser.add_argument("--agent-root-max-approval", choices=AGENT_APPROVAL_VALUES, help="system-wide root agent approval ceiling")
    parser.add_argument("--agent-root-max-minutes", type=int, metavar="MINUTES", help="system-wide root agent duration ceiling")
    updater = parser.add_mutually_exclusive_group()
    updater.add_argument("--enable-updater-tray", action="store_true", help="enable the AuraScan Updater tray icon")
    updater.add_argument("--disable-updater-tray", action="store_true", help="disable the AuraScan Updater tray icon")
    updater_autostart = parser.add_mutually_exclusive_group()
    updater_autostart.add_argument("--install-updater-autostart", action="store_true", help="install per-user AuraScan Updater autostart")
    updater_autostart.add_argument("--remove-updater-autostart", action="store_true", help="remove per-user AuraScan Updater autostart")
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument("--install-recovery", action="store_true", help="build and install the optional AuraScan Recovery boot entry")
    recovery.add_argument("--remove-recovery", action="store_true", help="remove the AuraScan-owned recovery boot entry")
    recovery_ai = parser.add_mutually_exclusive_group()
    recovery_ai.add_argument("--enable-recovery-ai", action="store_true", help="allow separately consented AI analysis inside AuraScan Recovery")
    recovery_ai.add_argument("--disable-recovery-ai", action="store_true", help="keep AI disabled inside AuraScan Recovery")
    recovery_refresh = parser.add_mutually_exclusive_group()
    recovery_refresh.add_argument("--enable-recovery-auto-refresh", action="store_true", help="refresh an enabled recovery image after relevant package changes")
    recovery_refresh.add_argument("--disable-recovery-auto-refresh", action="store_true", help="require manual recovery image refreshes")
    parser.add_argument("--recovery-wifi-profiles", choices=sorted(RECOVERY_WIFI_PROFILE_VALUES), help="permission for volatile use of saved NetworkManager Wi-Fi profiles")
    hook = parser.add_mutually_exclusive_group()
    hook.add_argument("--install-hook", action="store_true", help="install or repair a local pacman hook when no packaged hook is active")
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
    packaged_hook_path: Path = PACKAGED_HOOK_PATH,
    updater_config_home: Optional[Path] = None,
    updater_data_home: Optional[Path] = None,
    recovery_root: Path = Path("/"),
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_init_parser().parse_args(argv)
    target_env = env_path or user_env_path()
    existing = _safe_read_env(target_env)

    print("AuraScan first-run setup", file=stdout)
    print("AI analysis can send package metadata, PKGBUILD text, and install-script text to the selected provider endpoint.", file=stdout)
    print("LM Studio and llama.cpp presets are restricted to loopback and never fall back to a cloud provider.", file=stdout)

    updates: Dict[str, str] = {}
    configure_ai = bool(args.provider or args.base_url)
    if not configure_ai and not args.disable_ai:
        configure_ai = _prompt_yes_no("Configure an AI provider now?", input_func, default=False)

    if args.disable_ai or not configure_ai:
        updates[AI_ENABLED_ENV] = "0"
        print("AI analysis will stay disabled unless you enable it later.", file=stdout)
    else:
        provider = args.provider or _prompt_provider(input_func, existing.get(AI_PROVIDER_ENV, "openai"), stdout)
        spec = get_provider_spec(provider)
        if spec is None:
            print(f"Unsupported AI provider: {provider}", file=stderr)
            return 1

        same_provider = existing.get(AI_PROVIDER_ENV, "").strip().lower() == provider
        model_default = existing.get(AI_MODEL_ENV, "").strip() if same_provider else ""
        model_default = model_default or spec.default_model
        model = args.model
        if model is None:
            prompt_label = "Model ID" if spec.local else "Model"
            model = input_func(f"{prompt_label} [{model_default}]: ").strip() or model_default

        if spec.local:
            base_default = existing.get(AI_BASE_URL_ENV, "").strip() if same_provider else ""
            base_candidate = args.base_url or base_default or spec.default_base_url
            try:
                base_url = normalize_local_base_url(base_candidate)
            except AIProviderError as exc:
                print(f"Invalid local AI base URL: {exc}", file=stderr)
                return 1
            enabled = args.enable_ai
            if not args.enable_ai and not args.disable_ai:
                enabled = _prompt_yes_no(
                    "Enable local AI analysis for normal scans?",
                    input_func,
                    default=False,
                )
            updates.update({
                AI_PROVIDER_ENV: provider,
                AI_MODEL_ENV: model,
                AI_BASE_URL_ENV: base_url,
                AI_ENABLED_ENV: "1" if enabled else "0",
            })
            print(f"Configured {spec.label} at loopback endpoint {base_url}.", file=stdout)
            if not enabled:
                print("Local AI analysis is configured but disabled.", file=stdout)
        else:
            if args.base_url:
                print("--base-url is available only for LM Studio and llama.cpp providers.", file=stderr)
                return 1
            key = getpass_func(f"{spec.label} API key (input hidden): ").strip()
            if not key:
                print("No API key entered; leaving AI analysis disabled.", file=stdout)
                updates[AI_ENABLED_ENV] = "0"
            else:
                enabled = args.enable_ai
                if not args.enable_ai and not args.disable_ai:
                    enabled = _prompt_yes_no(
                        "Enable provider AI analysis for normal scans?",
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
                    print("AI analysis is configured but disabled.", file=stdout)

    configure_upgrade = (
        args.enable_upgrade_preflight
        or args.disable_upgrade_preflight
        or args.upgrade_aur_helper is not None
        or args.enable_upgrade_ai
        or args.disable_upgrade_ai
        or args.enable_kernel_module_autopilot
        or args.disable_kernel_module_autopilot
    )
    should_prompt_upgrade = not configure_upgrade and not (
        args.provider
        or args.base_url
        or args.enable_ai
        or args.disable_ai
        or args.enable_incident_monitor
        or args.disable_incident_monitor
        or args.enable_incident_ai
        or args.disable_incident_ai
        or args.incident_ai_evidence is not None
        or args.enable_incident_background_ai
        or args.disable_incident_background_ai
        or args.incident_auto_repair is not None
        or args.enable_instruction_monitor
        or args.disable_instruction_monitor
        or args.enable_instruction_ai
        or args.disable_instruction_ai
        or args.instruction_scan_mode is not None
        or args.agent_access is not None
        or args.agent_approval is not None
        or args.agent_output_sharing is not None
        or args.agent_session_timeout is not None
        or args.allow_agent_root
        or args.deny_agent_root
        or args.agent_root_max_approval is not None
        or args.agent_root_max_minutes is not None
        or args.install_recovery
        or args.remove_recovery
        or args.enable_recovery_ai
        or args.disable_recovery_ai
        or args.enable_recovery_auto_refresh
        or args.disable_recovery_auto_refresh
        or args.recovery_wifi_profiles is not None
        or args.install_hook
        or args.no_install_hook
    )
    if configure_upgrade or should_prompt_upgrade:
        existing_upgrade = resolve_upgrade_config(existing)
        upgrade_enabled = existing_upgrade.preflight_enabled if not existing_upgrade.error else True
        if args.enable_upgrade_preflight or args.enable_kernel_module_autopilot:
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
                    "Allow AI risk review during upgrade preflight when AI is enabled?",
                    input_func,
                    default=upgrade_ai_enabled,
                )
            updates[UPGRADE_PREFLIGHT_AI_ENV] = "1" if upgrade_ai_enabled else "0"
            autopilot_enabled = existing_upgrade.kernel_module_autopilot_enabled if not existing_upgrade.error else True
            if args.enable_kernel_module_autopilot:
                autopilot_enabled = True
            elif args.disable_kernel_module_autopilot:
                autopilot_enabled = False
            elif should_prompt_upgrade:
                autopilot_enabled = _prompt_yes_no(
                    "Enable kernel/module autopilot during upgrades?",
                    input_func,
                    default=autopilot_enabled,
                )
            updates[KERNEL_MODULE_AUTOPILOT_ENV] = "1" if autopilot_enabled else "0"
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

    configure_instruction_guard = (
        args.enable_instruction_monitor
        or args.disable_instruction_monitor
        or args.enable_instruction_ai
        or args.disable_instruction_ai
        or args.instruction_scan_mode is not None
    )
    should_prompt_instruction_guard = should_prompt_upgrade
    instruction_monitor_action = ""
    instruction_ai_action = ""
    if configure_instruction_guard or should_prompt_instruction_guard:
        existing_instruction = resolve_instruction_guard_preferences(existing)
        if existing_instruction.error:
            print(
                f"Existing Agent Instruction Guard configuration is invalid: {existing_instruction.error}",
                file=stderr,
            )
            return 1
        instruction_monitor_enabled = existing_instruction.monitor_enabled
        if args.enable_instruction_monitor:
            instruction_monitor_enabled = True
            instruction_monitor_action = "enable"
        elif args.disable_instruction_monitor:
            instruction_monitor_enabled = False
            instruction_monitor_action = "disable"
        elif should_prompt_instruction_guard:
            instruction_monitor_enabled = _prompt_yes_no(
                "Enable the unprivileged Agent Instruction Guard after login and every five minutes?",
                input_func,
                default=instruction_monitor_enabled,
            )
            if instruction_monitor_enabled != existing_instruction.monitor_enabled:
                instruction_monitor_action = "enable" if instruction_monitor_enabled else "disable"

        instruction_ai_enabled = existing_instruction.ai_enabled
        if args.enable_instruction_ai:
            instruction_ai_enabled = True
            instruction_ai_action = "enable"
        elif args.disable_instruction_ai:
            instruction_ai_enabled = False
            instruction_ai_action = "disable"
        elif should_prompt_instruction_guard and instruction_monitor_enabled:
            provider_env = dict(existing)
            provider_env.update(updates)
            if resolve_ai_config(provider_env).ready:
                instruction_ai_enabled = _prompt_yes_no(
                    "Allow the separate Agent Instruction Guard AI assistant to review bounded redacted evidence?",
                    input_func,
                    default=instruction_ai_enabled,
                )
                if instruction_ai_enabled != existing_instruction.ai_enabled:
                    instruction_ai_action = "enable" if instruction_ai_enabled else "disable"

        scan_mode = args.instruction_scan_mode or existing_instruction.scan_mode
        if should_prompt_instruction_guard and instruction_monitor_enabled and args.instruction_scan_mode is None:
            all_markdown = _prompt_yes_no(
                "Also analyze other Markdown content without adding it to the integrity baseline?",
                input_func,
                default=scan_mode == "all-markdown",
            )
            scan_mode = "all-markdown" if all_markdown else "agent-surfaces"
        updates[INSTRUCTION_MONITOR_ENABLED_ENV] = "1" if instruction_monitor_enabled else "0"
        updates[INSTRUCTION_AI_ENABLED_ENV] = "1" if instruction_ai_enabled else "0"
        updates[INSTRUCTION_SCAN_MODE_ENV] = scan_mode
        print("Configured Agent Instruction Guard defaults.", file=stdout)

    configure_incidents = (
        args.enable_incident_monitor
        or args.disable_incident_monitor
        or args.enable_incident_ai
        or args.disable_incident_ai
        or args.incident_ai_evidence is not None
        or args.enable_incident_background_ai
        or args.disable_incident_background_ai
        or args.incident_auto_repair is not None
    )
    should_prompt_incidents = should_prompt_upgrade
    incident_monitor_action = ""
    incident_background_action = ""
    incident_auto_repair_action = ""
    incident_previous_auto_repair = "off"
    if configure_incidents or should_prompt_incidents:
        existing_incidents = resolve_incident_config(existing)
        monitor_service_installed = (Path("/usr/lib/systemd/system") / INCIDENT_MONITOR_SERVICE).exists()
        monitor_default = (
            existing_incidents.monitor_enabled
            if INCIDENT_MONITOR_ENABLED_ENV in existing and not existing_incidents.error
            else monitor_service_installed
        )
        monitor_enabled = monitor_default
        if args.enable_incident_monitor:
            monitor_enabled = True
            incident_monitor_action = "enable"
        elif args.disable_incident_monitor:
            monitor_enabled = False
            incident_monitor_action = "disable"
        elif should_prompt_incidents:
            monitor_enabled = _prompt_yes_no(
                "Enable automatic previous-boot and weekly incident maintenance scans?",
                input_func,
                default=monitor_default,
            )
            if monitor_enabled:
                incident_monitor_action = "enable"
            elif existing_incidents.monitor_enabled:
                incident_monitor_action = "disable"

        incident_ai_enabled = existing_incidents.ai_enabled if not existing_incidents.error else True
        if args.enable_incident_ai:
            incident_ai_enabled = True
        elif args.disable_incident_ai:
            incident_ai_enabled = False
        elif should_prompt_incidents:
            incident_ai_enabled = _prompt_yes_no(
                "Allow AI explanation when you open an incident report?",
                input_func,
                default=incident_ai_enabled,
            )

        evidence_policy = existing_incidents.ai_evidence if not existing_incidents.error else "redacted"
        evidence_policy = args.incident_ai_evidence or evidence_policy
        background_ai_enabled = existing_incidents.background_ai_enabled if not existing_incidents.error else False
        if args.enable_incident_background_ai:
            background_ai_enabled = True
            incident_background_action = "enable"
        elif args.disable_incident_background_ai:
            background_ai_enabled = False
            incident_background_action = "disable"
        elif should_prompt_incidents and incident_ai_enabled:
            background_ai_enabled = _prompt_yes_no(
                "Analyze new incident findings with AI in the background while you are logged in?",
                input_func,
                default=background_ai_enabled,
            )
            if background_ai_enabled:
                incident_background_action = "enable"
            elif existing_incidents.background_ai_enabled:
                incident_background_action = "disable"
        elif not incident_ai_enabled:
            background_ai_enabled = False
            if existing_incidents.background_ai_enabled:
                incident_background_action = "disable"

        current_auto_repair = read_auto_repair_policy()
        incident_previous_auto_repair = current_auto_repair.policy if not current_auto_repair.error else "off"
        auto_repair_policy = current_auto_repair.policy if not current_auto_repair.error else "off"
        if args.incident_auto_repair is not None:
            auto_repair_policy = args.incident_auto_repair
            incident_auto_repair_action = auto_repair_policy
        elif should_prompt_incidents and monitor_enabled:
            auto_repair_policy = "safe" if _prompt_yes_no(
                "Allow Safe Autopilot to apply only reversible stale-lock and mirrorlist repairs?",
                input_func,
                default=auto_repair_policy == "safe",
            ) else "off"
            if auto_repair_policy != current_auto_repair.policy or current_auto_repair.error:
                incident_auto_repair_action = auto_repair_policy
        updates[INCIDENT_MONITOR_ENABLED_ENV] = "1" if monitor_enabled else "0"
        updates[INCIDENT_AI_ENABLED_ENV] = "1" if incident_ai_enabled else "0"
        updates[INCIDENT_AI_EVIDENCE_ENV] = evidence_policy
        updates[INCIDENT_BACKGROUND_AI_ENV] = "1" if background_ai_enabled else "0"
        print("Configured Incident Recovery Assistant defaults.", file=stdout)

    configure_agent = (
        args.agent_access is not None
        or args.agent_approval is not None
        or args.agent_output_sharing is not None
        or args.agent_session_timeout is not None
        or args.allow_agent_root
        or args.deny_agent_root
        or args.agent_root_max_approval is not None
        or args.agent_root_max_minutes is not None
    )
    should_prompt_agent = should_prompt_upgrade and updates.get(
        AI_ENABLED_ENV,
        existing.get(AI_ENABLED_ENV, "0"),
    ) == "1"
    agent_root_action: Optional[bool] = None
    agent_root_max_approval = "each-command"
    agent_root_max_minutes = AGENT_DEFAULT_SESSION_MINUTES
    if configure_agent or should_prompt_agent:
        existing_agent = resolve_agent_config(existing)
        access = existing_agent.access if not existing_agent.error else "guarded"
        approval = existing_agent.approval if not existing_agent.error else "each-command"
        output_sharing = existing_agent.output_sharing if not existing_agent.error else "redacted"
        session_minutes = (
            existing_agent.session_timeout_minutes
            if not existing_agent.error
            else AGENT_DEFAULT_SESSION_MINUTES
        )
        if args.agent_access is not None:
            access = args.agent_access
        elif should_prompt_agent:
            access = _prompt_agent_access(input_func, access, stdout)
        if args.agent_approval is not None:
            approval = args.agent_approval
        elif should_prompt_agent and access != "guarded":
            approval = _prompt_agent_approval(input_func, approval, stdout)
        requested_approval = approval
        approval = effective_agent_approval(access, approval)
        if requested_approval != approval:
            print(
                f"Repair Agent approval '{requested_approval}' is retained as a legacy input only; "
                "command-enabled profiles enforce fresh each-command confirmation.",
                file=stdout,
            )
        if args.agent_output_sharing is not None:
            output_sharing = args.agent_output_sharing
        elif should_prompt_agent and access != "guarded":
            output_sharing = _prompt_agent_output(input_func, output_sharing, stdout)
        if args.agent_session_timeout is not None:
            session_minutes = args.agent_session_timeout
        if session_minutes < 1 or session_minutes > AGENT_MAX_SESSION_MINUTES:
            print(
                f"Agent session timeout must be between 1 and {AGENT_MAX_SESSION_MINUTES} minutes.",
                file=stderr,
            )
            return 1

        current_root_policy = read_agent_root_policy()
        root_allowed = current_root_policy.allowed if not current_root_policy.error else False
        agent_root_max_approval = (
            current_root_policy.max_approval
            if not current_root_policy.error
            else "each-command"
        )
        agent_root_max_minutes = (
            current_root_policy.max_minutes
            if not current_root_policy.error
            else AGENT_DEFAULT_SESSION_MINUTES
        )
        if args.allow_agent_root:
            root_allowed = True
            agent_root_action = True
        elif args.deny_agent_root:
            root_allowed = False
            agent_root_action = False
        elif should_prompt_agent and access == "root-shell":
            print(
                "Policy-gated root repair permits only allowlisted absolute read-only diagnostics "
                "and constrained /usr/bin/pacman workflows. Remote acquisition, arbitrary "
                "executables, AUR/build tools, interpreters, and dynamic code are refused. "
                "Approved package changes can still alter installed software and system state.",
                file=stdout,
            )
            root_allowed = _prompt_yes_no(
                "Allow separately consented policy-gated root repair sessions?",
                input_func,
                default=False,
            )
            if root_allowed != current_root_policy.allowed or current_root_policy.error:
                agent_root_action = root_allowed
        if args.agent_root_max_approval is not None:
            agent_root_max_approval = args.agent_root_max_approval
            agent_root_action = root_allowed
        elif agent_root_action is True:
            agent_root_max_approval = approval
        agent_root_max_approval = effective_agent_approval(
            "root-shell",
            agent_root_max_approval,
        )
        if args.agent_root_max_minutes is not None:
            agent_root_max_minutes = args.agent_root_max_minutes
            agent_root_action = root_allowed
        elif agent_root_action is True:
            agent_root_max_minutes = session_minutes
        if (
            agent_root_max_minutes < 1
            or agent_root_max_minutes > AGENT_MAX_SESSION_MINUTES
        ):
            print(
                f"Agent root session ceiling must be between 1 and {AGENT_MAX_SESSION_MINUTES} minutes.",
                file=stderr,
            )
            return 1

        updates[AGENT_ACCESS_ENV] = access
        updates[AGENT_APPROVAL_ENV] = approval
        updates[AGENT_OUTPUT_SHARING_ENV] = output_sharing
        updates[AGENT_SESSION_TIMEOUT_ENV] = str(session_minutes)
        print(
            f"Configured Policy-Gated Repair Agent defaults: {access}, {approval}, {output_sharing}.",
            file=stdout,
        )

    configure_updater = (
        args.enable_updater_tray
        or args.disable_updater_tray
        or args.install_updater_autostart
        or args.remove_updater_autostart
    )
    should_prompt_updater = should_prompt_upgrade
    updater_autostart_action = ""
    if configure_updater or should_prompt_updater:
        existing_updater = resolve_updater_config(existing)
        updater_enabled = existing_updater.tray_enabled if not existing_updater.error else False
        updater_autostart_enabled = existing_updater.autostart_enabled if not existing_updater.error else False
        updater_terminal = existing_updater.terminal if not existing_updater.error else "auto"

        if args.enable_updater_tray or args.install_updater_autostart:
            updater_enabled = True
        elif args.disable_updater_tray:
            updater_enabled = False
        elif should_prompt_updater:
            updater_enabled = _prompt_yes_no(
                "Enable AuraScan Updater tray icon at login?",
                input_func,
                default=updater_enabled,
            )

        if args.install_updater_autostart:
            updater_autostart_enabled = True
            updater_autostart_action = "install"
        elif args.remove_updater_autostart:
            updater_autostart_enabled = False
            updater_autostart_action = "remove"
            if not args.enable_updater_tray:
                updater_enabled = False
        elif should_prompt_updater and updater_enabled:
            updater_autostart_enabled = True
            updater_autostart_action = "install"
        elif should_prompt_updater and not updater_enabled and updater_autostart_enabled:
            updater_autostart_enabled = False
            updater_autostart_action = "remove"

        updates[UPDATER_TRAY_ENABLED_ENV] = "1" if updater_enabled else "0"
        updates[UPDATER_AUTOSTART_ENV] = "1" if updater_autostart_enabled else "0"
        updates[UPDATER_TERMINAL_ENV] = updater_terminal or "auto"
        print("Configured AuraScan Updater tray defaults.", file=stdout)

    configure_recovery = (
        args.install_recovery
        or args.remove_recovery
        or args.enable_recovery_ai
        or args.disable_recovery_ai
        or args.enable_recovery_auto_refresh
        or args.disable_recovery_auto_refresh
        or args.recovery_wifi_profiles is not None
    )
    recovery_action = ""
    recovery_ready = False
    recovery_state: Dict[str, object] = {}
    if should_prompt_upgrade or configure_recovery:
        try:
            recovery_state = recovery_status(root=recovery_root, runner=runner)
            installation_state = recovery_state.get("installation", {})
            recovery_ready = bool(
                isinstance(installation_state, Mapping)
                and installation_state.get("ready")
                and installation_state.get("esp_space_ready")
            )
        except Exception:
            recovery_ready = False
        install_recovery = bool(args.install_recovery)
        if args.remove_recovery:
            install_recovery = False
            recovery_action = "remove"
        elif should_prompt_upgrade and recovery_ready:
            installed = bool(recovery_state.get("policy", {}).get("enabled")) if isinstance(recovery_state.get("policy"), Mapping) else False
            install_recovery = _prompt_yes_no(
                "Install the optional AuraScan Recovery boot environment?",
                input_func,
                default=True,
            )
            if install_recovery and not installed:
                recovery_action = "install"
            elif not install_recovery and installed:
                recovery_action = "remove"
        elif args.install_recovery:
            recovery_action = "install"

        current_recovery = resolve_recovery_config(existing)
        recovery_ai_enabled = current_recovery.ai_enabled if not current_recovery.error else False
        if args.enable_recovery_ai:
            recovery_ai_enabled = True
        elif args.disable_recovery_ai:
            recovery_ai_enabled = False
        elif should_prompt_upgrade and install_recovery:
            recovery_ai_enabled = _prompt_yes_no(
                "Allow AuraScan Recovery to contact your configured AI provider after networking is available?",
                input_func,
                default=recovery_ai_enabled,
            )
        auto_refresh = current_recovery.auto_refresh if not current_recovery.error else True
        if args.enable_recovery_auto_refresh:
            auto_refresh = True
        elif args.disable_recovery_auto_refresh:
            auto_refresh = False
        wifi_profiles = args.recovery_wifi_profiles or (current_recovery.wifi_profiles if not current_recovery.error else "ask")
        if should_prompt_upgrade and install_recovery and args.recovery_wifi_profiles is None:
            wifi_profiles = _prompt_recovery_wifi_profiles(input_func, wifi_profiles, stdout)
        updates[RECOVERY_AI_ENABLED_ENV] = "1" if recovery_ai_enabled else "0"
        updates[RECOVERY_AUTO_REFRESH_ENV] = "1" if auto_refresh else "0"
        updates[RECOVERY_WIFI_PROFILES_ENV] = wifi_profiles
        if install_recovery:
            print("Configured AuraScan Recovery consent and refresh defaults.", file=stdout)
        elif should_prompt_upgrade and not recovery_ready:
            print("AuraScan Recovery installation is unavailable until UEFI, bootloader, mkosi, and ukify checks pass.", file=stdout)

    write_user_env(updates, path=target_env)
    print(f"Wrote user config: {target_env}", file=stdout)

    if agent_root_action is not None:
        agent_ok, agent_message = configure_agent_root_policy(
            agent_root_action,
            agent_root_max_approval,
            agent_root_max_minutes,
            runner=runner,
            helper=executable_path,
        )
        print(agent_message, file=stdout if agent_ok else stderr)
        if not agent_ok:
            rollback = {
                AGENT_ACCESS_ENV: existing.get(AGENT_ACCESS_ENV, "guarded"),
                AGENT_APPROVAL_ENV: existing.get(AGENT_APPROVAL_ENV, "each-command"),
                AGENT_OUTPUT_SHARING_ENV: existing.get(AGENT_OUTPUT_SHARING_ENV, "redacted"),
                AGENT_SESSION_TIMEOUT_ENV: existing.get(
                    AGENT_SESSION_TIMEOUT_ENV,
                    str(AGENT_DEFAULT_SESSION_MINUTES),
                ),
            }
            write_user_env(rollback, path=target_env)
            return 1

    if incident_auto_repair_action:
        auto_ok, auto_message = configure_auto_repair_policy(incident_auto_repair_action, runner=runner)
        print(auto_message, file=stdout if auto_ok else stderr)
        if not auto_ok:
            return 1

    if incident_monitor_action:
        desired = incident_monitor_action == "enable"
        monitor_ok, monitor_message = set_incident_monitor_enabled(desired, runner=runner)
        print(monitor_message, file=stdout if monitor_ok else stderr)
        if not monitor_ok:
            previous = existing.get(INCIDENT_MONITOR_ENABLED_ENV, "0")
            write_user_env({INCIDENT_MONITOR_ENABLED_ENV: previous}, path=target_env)
            if incident_auto_repair_action and incident_auto_repair_action != incident_previous_auto_repair:
                configure_auto_repair_policy(incident_previous_auto_repair, runner=runner)
            return 1

    if incident_background_action:
        desired = incident_background_action == "enable"
        background_ok, background_message = set_background_ai_enabled(desired, runner=runner, env_path=target_env)
        print(background_message, file=stdout if background_ok else stderr)
        if not background_ok:
            previous = existing.get(INCIDENT_BACKGROUND_AI_ENV, "0")
            write_user_env({INCIDENT_BACKGROUND_AI_ENV: previous}, path=target_env)
            return 1

    instruction_rollback_config = {
        INSTRUCTION_MONITOR_ENABLED_ENV: existing.get(INSTRUCTION_MONITOR_ENABLED_ENV, "0"),
        INSTRUCTION_AI_ENABLED_ENV: existing.get(INSTRUCTION_AI_ENABLED_ENV, "0"),
        INSTRUCTION_SCAN_MODE_ENV: existing.get(INSTRUCTION_SCAN_MODE_ENV, "agent-surfaces"),
    }
    instruction_monitor_snapshot = None
    instruction_ai_snapshot = None
    if instruction_monitor_action:
        instruction_monitor_snapshot = _capture_user_timer_state(
            timer=INSTRUCTION_MONITOR_TIMER,
            service=INSTRUCTION_MONITOR_SERVICE,
            runner=runner,
        )
        if instruction_monitor_snapshot is None:
            write_user_env(instruction_rollback_config, path=target_env)
            print(
                "Could not safely capture the monitor's prior user-unit state.",
                file=stderr,
            )
            return 1
    if instruction_ai_action:
        instruction_ai_snapshot = _capture_user_timer_state(
            timer=INSTRUCTION_ASSISTANT_TIMER,
            service=INSTRUCTION_ASSISTANT_SERVICE,
            runner=runner,
        )
        if instruction_ai_snapshot is None:
            write_user_env(instruction_rollback_config, path=target_env)
            print(
                "Could not safely capture the AI assistant's prior user-unit state.",
                file=stderr,
            )
            return 1

    if instruction_monitor_action:
        desired = instruction_monitor_action == "enable"
        monitor_ok, monitor_message = set_instruction_monitor_enabled(
            desired,
            runner=runner,
            env_path=target_env,
            write_config=False,
        )
        print(monitor_message, file=stdout if monitor_ok else stderr)
        if not monitor_ok:
            rollback_ok = _restore_user_timer_state(
                instruction_monitor_snapshot,
                timer=INSTRUCTION_MONITOR_TIMER,
                service=INSTRUCTION_MONITOR_SERVICE,
                runner=runner,
            )
            write_user_env(instruction_rollback_config, path=target_env)
            if not rollback_ok:
                print("The monitor's prior user-unit state could not be fully restored.", file=stderr)
            return 1

    if instruction_ai_action:
        desired = instruction_ai_action == "enable"
        provider_env = dict(os.environ)
        provider_env.update(_safe_read_env(target_env))
        ai_ok, ai_message = set_instruction_ai_enabled(
            desired,
            runner=runner,
            env_path=target_env,
            env=provider_env,
            write_config=False,
        )
        print(ai_message, file=stdout if ai_ok else stderr)
        if not ai_ok:
            ai_rollback_ok = _restore_user_timer_state(
                instruction_ai_snapshot,
                timer=INSTRUCTION_ASSISTANT_TIMER,
                service=INSTRUCTION_ASSISTANT_SERVICE,
                runner=runner,
            )
            monitor_rollback_ok = True
            if instruction_monitor_snapshot is not None:
                monitor_rollback_ok = _restore_user_timer_state(
                    instruction_monitor_snapshot,
                    timer=INSTRUCTION_MONITOR_TIMER,
                    service=INSTRUCTION_MONITOR_SERVICE,
                    runner=runner,
                )
            write_user_env(instruction_rollback_config, path=target_env)
            if not ai_rollback_ok or not monitor_rollback_ok:
                print("The prior Instruction Guard user-unit state could not be fully restored.", file=stderr)
            return 1

    updater_paths = updater_desktop_paths(config_home=updater_config_home, data_home=updater_data_home)
    if updater_autostart_action == "install":
        updater_result = install_updater_autostart(paths=updater_paths)
        print(updater_result.message, file=stdout if updater_result.ok else stderr)
        if not updater_result.ok:
            return 1
    elif updater_autostart_action == "remove":
        updater_result = remove_updater_autostart(paths=updater_paths)
        print(updater_result.message, file=stdout if updater_result.ok else stderr)
        if not updater_result.ok:
            return 1

    if recovery_action:
        command = ["sudo", str(executable_path), "recovery", "--install" if recovery_action == "install" else "--remove"]
        if recovery_action == "install":
            command.extend([
                "--opted-uid", str(os.getuid()),
                "--wifi-profiles", updates.get(RECOVERY_WIFI_PROFILES_ENV, "ask"),
                "--refresh-policy", "automatic" if updates.get(RECOVERY_AUTO_REFRESH_ENV, "1") == "1" else "manual",
            ])
        result = runner(command, capture_output=True, text=True, check=False)
        message = (result.stdout or result.stderr or "").strip()
        if message:
            print(message, file=stdout if result.returncode == 0 else stderr)
        if result.returncode != 0:
            rollback = {
                RECOVERY_AI_ENABLED_ENV: existing.get(RECOVERY_AI_ENABLED_ENV, "0"),
                RECOVERY_AUTO_REFRESH_ENV: existing.get(RECOVERY_AUTO_REFRESH_ENV, "1"),
                RECOVERY_WIFI_PROFILES_ENV: existing.get(RECOVERY_WIFI_PROFILES_ENV, "ask"),
            }
            write_user_env(rollback, path=target_env)
            return 1

    if args.check_ai:
        check_env = dict(os.environ)
        check_env.update(_safe_read_env(target_env))
        check = _check_ai_connectivity(check_env, urlopen=urlopen)
        print(_format_check_line(check), file=stdout)

    install_hook = args.install_hook
    if not args.no_install_hook:
        if is_release_safe_hook_template(hook_path):
            print(f"Pacman hook is already active at {hook_path}.", file=stdout)
            return 0
        if not hook_path.exists() and is_release_safe_hook_template(packaged_hook_path):
            print(
                f"Pacman hook is already active at {packaged_hook_path}; no local override is needed.",
                file=stdout,
            )
            return 0
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
    updater_config_home: Optional[Path] = None,
    updater_data_home: Optional[Path] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    qt_binding_finder: Optional[Callable[[], str]] = None,
    runner: Callable = subprocess.run,
    os_release_path: Path = Path("/etc/os-release"),
    incident_service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MONITOR_SERVICE,
    incident_maintenance_service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MAINTENANCE_SERVICE,
    incident_maintenance_timer_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MAINTENANCE_TIMER,
    incident_system_root: Path = INCIDENT_SYSTEM_ROOT,
    incident_background_unit_root: Path = INCIDENT_USER_UNIT_ROOT,
    instruction_unit_root: Path = INSTRUCTION_USER_UNIT_ROOT,
    instruction_state_root: Optional[Path] = None,
    incident_safe_service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_SAFE_AUTOPILOT_SERVICE,
    incident_auto_repair_policy_path: Path = INCIDENT_AUTO_REPAIR_POLICY_PATH,
    incident_auto_repair_policy_uid: int = 0,
    incident_user_root: Optional[Path] = None,
    journal_root: Path = Path("/var/log/journal"),
    pstore_root: Path = Path("/sys/fs/pstore"),
    recovery_root: Path = Path("/"),
    followup_root: Optional[Path] = None,
    agent_root_policy_path: Path = AGENT_ROOT_POLICY_PATH,
    agent_root_policy_uid: int = 0,
    agent_audit_root: Optional[Path] = None,
    agent_runtime_root: Path = Path("/run/aurascan-agent"),
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
        updater_config_home=updater_config_home,
        updater_data_home=updater_data_home,
        which=which,
        qt_binding_finder=qt_binding_finder,
        runner=runner,
        os_release_path=os_release_path,
        incident_service_path=incident_service_path,
        incident_maintenance_service_path=incident_maintenance_service_path,
        incident_maintenance_timer_path=incident_maintenance_timer_path,
        incident_system_root=incident_system_root,
        incident_background_unit_root=incident_background_unit_root,
        instruction_unit_root=instruction_unit_root,
        instruction_state_root=instruction_state_root,
        incident_safe_service_path=incident_safe_service_path,
        incident_auto_repair_policy_path=incident_auto_repair_policy_path,
        incident_auto_repair_policy_uid=incident_auto_repair_policy_uid,
        incident_user_root=incident_user_root,
        journal_root=journal_root,
        pstore_root=pstore_root,
        recovery_root=recovery_root,
        followup_root=followup_root,
        agent_root_policy_path=agent_root_policy_path,
        agent_root_policy_uid=agent_root_policy_uid,
        agent_audit_root=agent_audit_root,
        agent_runtime_root=agent_runtime_root,
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
    updater_config_home: Optional[Path] = None,
    updater_data_home: Optional[Path] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    qt_binding_finder: Optional[Callable[[], str]] = None,
    runner: Callable = subprocess.run,
    os_release_path: Path = Path("/etc/os-release"),
    incident_service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MONITOR_SERVICE,
    incident_maintenance_service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MAINTENANCE_SERVICE,
    incident_maintenance_timer_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MAINTENANCE_TIMER,
    incident_system_root: Path = INCIDENT_SYSTEM_ROOT,
    incident_background_unit_root: Path = INCIDENT_USER_UNIT_ROOT,
    instruction_unit_root: Path = INSTRUCTION_USER_UNIT_ROOT,
    instruction_state_root: Optional[Path] = None,
    incident_safe_service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_SAFE_AUTOPILOT_SERVICE,
    incident_auto_repair_policy_path: Path = INCIDENT_AUTO_REPAIR_POLICY_PATH,
    incident_auto_repair_policy_uid: int = 0,
    incident_user_root: Optional[Path] = None,
    journal_root: Path = Path("/var/log/journal"),
    pstore_root: Path = Path("/sys/fs/pstore"),
    recovery_root: Path = Path("/"),
    followup_root: Optional[Path] = None,
    agent_root_policy_path: Path = AGENT_ROOT_POLICY_PATH,
    agent_root_policy_uid: int = 0,
    agent_audit_root: Optional[Path] = None,
    agent_runtime_root: Path = Path("/run/aurascan-agent"),
) -> List[DoctorCheck]:
    checks: List[DoctorCheck] = []
    file_values = _safe_read_env(env_path)
    effective_env = dict(os.environ if env is None else env)
    effective_env.update(file_values)

    distro = detect_distro(os_release_path)
    distro_status = "ok" if distro.support_tier != "unsupported" else "warn"
    tier_label = distro.support_tier.replace("_", " ")
    checks.append(DoctorCheck(
        "distro_compatibility",
        distro_status,
        f"Distro compatibility: {distro.name} ({tier_label})",
        distro.to_dict(),
    ))

    capabilities = detect_package_manager_capabilities(which)
    found_tools = capabilities.to_dict()["found"]
    checks.append(DoctorCheck(
        "package_manager_capabilities",
        "ok" if capabilities.found("pacman") else "warn",
        "Package-manager tools found: " + (", ".join(found_tools) if found_tools else "none"),
        capabilities.to_dict(),
    ))

    desktop = detect_desktop_session(effective_env)
    desktop_status = "warn" if desktop.tray_support in {"extension_required", "manual_tray_host", "unknown"} else "ok"
    checks.append(DoctorCheck(
        "desktop_session",
        desktop_status,
        f"Desktop session: {desktop.primary_desktop} ({desktop.session_type or 'unknown'}); tray support: {desktop.tray_support}",
        desktop.to_dict(),
    ))

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
    elif ai_config.error == "invalid_base_url":
        checks.append(DoctorCheck("ai_provider", "error", f"Invalid loopback URL in {AI_BASE_URL_ENV}"))
    else:
        spec = get_provider_spec(ai_config.provider)
        label = spec.label if spec else ai_config.provider
        provider_details = {
            "provider": ai_config.provider,
            "model": ai_config.model,
            "local": bool(spec and spec.local),
        }
        if spec and spec.local:
            provider_details["base_url"] = ai_config.base_url
        checks.append(DoctorCheck("ai_provider", "ok", f"AI provider: {label}", provider_details))
        if ai_config.enabled:
            if spec and spec.local:
                checks.append(DoctorCheck(
                    "ai_authentication",
                    "ok",
                    "Local AI endpoint is keyless" if not ai_config.api_key_present else "Optional local AI token is configured",
                    {
                        "authentication_required": False,
                        "token_present": ai_config.api_key_present,
                        "key_env": ai_config.key_env,
                    },
                ))
            elif ai_config.api_key_present:
                checks.append(DoctorCheck("ai_key", "ok", f"AI key present in {ai_config.key_env}", {"key_env": ai_config.key_env, "key_present": True}))
            else:
                checks.append(DoctorCheck("ai_key", "error", f"AI is enabled but {ai_config.key_env} is not set", {"key_env": ai_config.key_env, "key_present": False}))
        else:
            checks.append(DoctorCheck("ai_enabled", "warn", "AI analysis is disabled", {"enabled": False}))

    if check_ai:
        checks.append(_check_ai_connectivity(effective_env, urlopen=urlopen))

    instruction_preferences = resolve_instruction_guard_preferences(effective_env)
    if instruction_preferences.error:
        checks.append(DoctorCheck(
            "instruction_guard_config",
            "error",
            f"Agent Instruction Guard configuration is invalid: {instruction_preferences.error}",
        ))
    elif instruction_preferences.monitor_enabled:
        checks.append(DoctorCheck(
            "instruction_guard_config",
            "ok",
            f"Agent Instruction Guard is enabled in {instruction_preferences.scan_mode} mode",
            {
                "monitor_enabled": True,
                "ai_enabled": instruction_preferences.ai_enabled,
                "scan_mode": instruction_preferences.scan_mode,
            },
        ))
    else:
        checks.append(DoctorCheck(
            "instruction_guard_config",
            "warn",
            "Agent Instruction Guard monitor is disabled until the user opts in",
            {
                "monitor_enabled": False,
                "ai_enabled": instruction_preferences.ai_enabled,
                "scan_mode": instruction_preferences.scan_mode,
            },
        ))

    monitor_units_installed = all(
        (instruction_unit_root / name).is_file()
        for name in ("aurascan-instruction-monitor.service", "aurascan-instruction-monitor.timer")
    )
    assistant_units_installed = all(
        (instruction_unit_root / name).is_file()
        for name in ("aurascan-instruction-assistant.service", "aurascan-instruction-assistant.timer")
    )
    if monitor_units_installed or assistant_units_installed:
        instruction_units = instruction_guard_unit_status(
            runner=runner,
            unit_root=instruction_unit_root,
        )
    else:
        instruction_units = {
            "monitor_installed": False,
            "assistant_installed": False,
            "monitor_timer_enabled": "not-found",
            "monitor_timer_active": "inactive",
            "assistant_timer_enabled": "not-found",
            "assistant_timer_active": "inactive",
        }
    monitor_enabled_state = instruction_units.get("monitor_timer_enabled")
    monitor_active_state = instruction_units.get("monitor_timer_active")
    monitor_matches_enabled = bool(
        instruction_units.get("monitor_installed")
        and monitor_enabled_state == "enabled"
        and monitor_active_state == "active"
    )
    monitor_matches_disabled = bool(
        instruction_units.get("monitor_installed")
        and monitor_enabled_state == "disabled"
        and monitor_active_state == "inactive"
    )
    if instruction_preferences.monitor_enabled:
        checks.append(DoctorCheck(
            "instruction_guard_monitor",
            "ok" if monitor_matches_enabled else "error",
            "Agent Instruction Guard monitor timer is installed, enabled, and active"
            if monitor_matches_enabled
            else "Agent Instruction Guard is enabled in config but its user timer is not healthy",
            instruction_units,
        ))
    elif monitor_matches_disabled:
        checks.append(DoctorCheck(
            "instruction_guard_monitor",
            "ok",
            "Agent Instruction Guard monitor timer is installed, disabled, and inactive",
            instruction_units,
        ))
    elif monitor_units_installed:
        checks.append(DoctorCheck(
            "instruction_guard_monitor",
            "error",
            "Agent Instruction Guard is disabled in config but its user timer is enabled, active, or unavailable",
            instruction_units,
        ))
    else:
        checks.append(DoctorCheck(
            "instruction_guard_monitor",
            "warn",
            "Agent Instruction Guard user units are not installed",
            instruction_units,
        ))

    assistant_enabled_state = instruction_units.get("assistant_timer_enabled")
    assistant_active_state = instruction_units.get("assistant_timer_active")
    assistant_matches_enabled = bool(
        instruction_units.get("assistant_installed")
        and assistant_enabled_state == "enabled"
        and assistant_active_state == "active"
    )
    assistant_matches_disabled = bool(
        instruction_units.get("assistant_installed")
        and assistant_enabled_state == "disabled"
        and assistant_active_state == "inactive"
    )
    if instruction_preferences.ai_enabled:
        assistant_healthy = (
            ai_config.ready
            and assistant_matches_enabled
        )
        checks.append(DoctorCheck(
            "instruction_guard_ai",
            "ok" if assistant_healthy else "error",
            "Agent Instruction Guard raise-only AI assistant is ready"
            if assistant_healthy
            else "Instruction Guard AI consent is enabled but the provider or assistant timer is not ready",
            {
                "consent_enabled": True,
                "provider_ready": ai_config.ready,
                "assistant_installed": instruction_units.get("assistant_installed"),
                "assistant_timer_enabled": instruction_units.get("assistant_timer_enabled"),
                "assistant_timer_active": instruction_units.get("assistant_timer_active"),
            },
        ))
    elif assistant_matches_disabled:
        checks.append(DoctorCheck(
            "instruction_guard_ai",
            "ok",
            "Agent Instruction Guard AI consent is disabled and its assistant timer is inactive",
            {
                "consent_enabled": False,
                "provider_ready": ai_config.ready,
                "assistant_installed": instruction_units.get("assistant_installed"),
                "assistant_timer_enabled": assistant_enabled_state,
                "assistant_timer_active": assistant_active_state,
            },
        ))
    elif assistant_units_installed:
        checks.append(DoctorCheck(
            "instruction_guard_ai",
            "error",
            "Instruction Guard AI consent is disabled but its assistant timer is enabled, active, or unavailable",
            {
                "consent_enabled": False,
                "provider_ready": ai_config.ready,
                "assistant_installed": instruction_units.get("assistant_installed"),
                "assistant_timer_enabled": assistant_enabled_state,
                "assistant_timer_active": assistant_active_state,
            },
        ))
    else:
        checks.append(DoctorCheck(
            "instruction_guard_ai",
            "warn",
            "Agent Instruction Guard AI consent is disabled and its user units are not installed",
            {
                "consent_enabled": False,
                "provider_ready": ai_config.ready,
                "assistant_installed": False,
                "assistant_timer_enabled": assistant_enabled_state,
                "assistant_timer_active": assistant_active_state,
            },
        ))

    try:
        from aurascan.core.instruction_guard import (
            default_instruction_guard_state_root,
            instruction_guard_status,
        )

        if instruction_state_root is not None:
            resolved_instruction_state = instruction_state_root
        elif env is not None and "HOME" not in env and "XDG_STATE_HOME" not in env:
            # Injected test/diagnostic environments must never fall through to
            # the process owner's real home directory.
            resolved_instruction_state = env_path.parent / "instruction-guard-state"
        else:
            resolved_instruction_state = default_instruction_guard_state_root(effective_env)
        instruction_state = instruction_guard_status(
            state_root=resolved_instruction_state,
            env=effective_env,
        )
    except (ImportError, OSError, TypeError, ValueError) as exc:
        resolved_instruction_state = (
            instruction_state_root
            or (env_path.parent / "instruction-guard-state" if env is not None else None)
        )
        instruction_state = {"state": "unavailable", "error": str(exc)}
    if resolved_instruction_state is not None and not Path(resolved_instruction_state).exists():
        checks.append(DoctorCheck(
            "instruction_guard_state",
            "ok",
            "Agent Instruction Guard private state will be created with 0700 permissions on first scan",
        ))
    elif instruction_state.get("state") == "unavailable":
        checks.append(DoctorCheck(
            "instruction_guard_state",
            "error",
            "Agent Instruction Guard private state ownership, permissions, or schema are unsafe",
            dict(instruction_state),
        ))
    else:
        checks.append(DoctorCheck(
            "instruction_guard_state",
            "ok",
            "Agent Instruction Guard private state permissions and schema are valid",
            dict(instruction_state),
        ))

    notifier = which("notify-send")
    checks.append(DoctorCheck(
        "instruction_guard_notifications",
        "ok" if notifier else "warn",
        "Desktop notifications are available; Agent Instruction Guard messages contain no paths or snippets"
        if notifier
        else "notify-send is unavailable; findings remain visible in the tray and CLI review state",
        {"notify_send": bool(notifier)},
    ))

    resolved_followup_root = (
        followup_root
        or (incident_user_root.parent / "follow-up" if incident_user_root is not None else None)
    )
    followup = followup_doctor_status(effective_env, root=resolved_followup_root)
    if followup.get("error"):
        checks.append(DoctorCheck(
            "followup_assistant",
            "error",
            f"Contextual follow-up storage is unsafe: {followup['error']}",
            followup,
        ))
    elif followup.get("provider_ready"):
        latest_id = str(followup.get("latest_context_id") or "")
        latest_note = f"; latest context: {latest_id}" if latest_id else ""
        checks.append(DoctorCheck(
            "followup_assistant",
            "ok",
            "Contextual AI follow-up is ready" + latest_note,
            followup,
        ))
    else:
        checks.append(DoctorCheck(
            "followup_assistant",
            "warn",
            "Contextual AI follow-up is unavailable until an AI provider is ready",
            followup,
        ))

    resolved_agent_audit_root = (
        agent_audit_root
        or (incident_user_root.parent / "agent" if incident_user_root is not None else None)
    )
    agent = agent_doctor_status(
        effective_env,
        policy_path=agent_root_policy_path,
        policy_uid=agent_root_policy_uid,
        audit_root=resolved_agent_audit_root,
        runtime_root=agent_runtime_root,
        which=which,
        runner=runner,
    )
    agent_config = agent["config"]
    root_policy = agent["root_policy"]
    if agent_config.get("error"):
        checks.append(DoctorCheck(
            "repair_agent",
            "error",
            f"Policy-Gated Repair Agent configuration is invalid: {agent_config['error']}",
            agent,
        ))
    elif agent_config.get("access") == "guarded":
        checks.append(DoctorCheck(
            "repair_agent",
            "ok",
            "Policy-Gated Repair Agent is limited to guarded AuraScan-owned tools",
            agent,
        ))
    elif not ai_config.ready:
        checks.append(DoctorCheck(
            "repair_agent",
            "warn",
            "Policy-Gated Repair Agent command access is configured but foreground AI is unavailable",
            agent,
        ))
    else:
        checks.append(DoctorCheck(
            "repair_agent",
            "ok",
            f"Policy-Gated Repair Agent access is configured for {agent_config.get('access')}",
            agent,
        ))
    if root_policy.get("error"):
        checks.append(DoctorCheck(
            "repair_agent_root_policy",
            "error",
            f"Policy-Gated Repair Agent root policy is unsafe or invalid: {root_policy['error']}",
            root_policy,
        ))
    elif root_policy.get("allowed"):
        checks.append(DoctorCheck(
            "repair_agent_root_policy",
            "warn",
            "Policy-gated root repair sessions are allowed but still require a typed per-session grant",
            root_policy,
        ))
    else:
        checks.append(DoctorCheck(
            "repair_agent_root_policy",
            "ok",
            "Policy-gated root repair sessions are disabled",
            root_policy,
        ))
    if agent.get("audit_storage_exists") and not agent.get("audit_storage_safe"):
        checks.append(DoctorCheck(
            "repair_agent_audit",
            "error",
            "Repair Agent audit storage ownership or permissions are unsafe",
            agent,
        ))
    else:
        checks.append(DoctorCheck(
            "repair_agent_audit",
            "ok",
            "Repair Agent private audit storage is ready"
            if agent.get("audit_storage_exists")
            else "Repair Agent private audit storage will be created on first use",
            agent,
        ))
    if int(agent.get("stale_root_sessions") or 0):
        checks.append(DoctorCheck(
            "repair_agent_sessions",
            "warn",
            f"Repair Agent found {agent['stale_root_sessions']} stale root session record(s)",
            agent,
        ))
    elif not agent.get("stale_root_sessions_checked"):
        checks.append(DoctorCheck(
            "repair_agent_sessions",
            "warn",
            "Repair Agent root session cleanup status requires root while runtime records exist",
            agent,
        ))
    else:
        checks.append(DoctorCheck(
            "repair_agent_sessions",
            "ok",
            "No stale Repair Agent root sessions were detected",
            agent,
        ))

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
                "kernel_module_autopilot_enabled": upgrade_config.kernel_module_autopilot_enabled,
            },
        ))
        if upgrade_config.aur_helper in {"paru", "yay", "shelly"} and not which(upgrade_config.aur_helper):
            checks.append(DoctorCheck(
                "upgrade_aur_helper",
                "warn",
                f"Configured AUR helper {upgrade_config.aur_helper} was not found in PATH",
                {"aur_helper": upgrade_config.aur_helper},
            ))
    else:
        checks.append(DoctorCheck("upgrade_preflight", "warn", "Upgrade preflight is disabled", {"enabled": False}))

    installed_packages = _doctor_command_lines(runner, ["pacman", "-Qq"]) if which("pacman") else []
    installed_kernels = sorted(name for name in installed_packages if is_kernel_base_package(name))
    module_families = detect_module_families(installed_packages)
    dkms_available = bool(which("dkms"))
    post_upgrade_ready = bool(which("pacman") and Path("/usr/lib/modules").exists())
    if upgrade_config.error:
        checks.append(DoctorCheck("kernel_module_autopilot", "error", upgrade_config.error))
    elif upgrade_config.kernel_module_autopilot_enabled and upgrade_config.preflight_enabled:
        checks.append(DoctorCheck(
            "kernel_module_autopilot",
            "ok",
            "Kernel/module autopilot is enabled",
            {
                "enabled": True,
                "installed_kernels": installed_kernels,
                "module_families": module_families,
                "dkms_available": dkms_available,
                "post_upgrade_aftercare_ready": post_upgrade_ready,
            },
        ))
    else:
        checks.append(DoctorCheck("kernel_module_autopilot", "warn", "Kernel/module autopilot is disabled", {"enabled": False}))
    if "dkms" in module_families and dkms_available:
        checks.append(DoctorCheck("kernel_module_dkms", "ok", "DKMS command is available for kernel/module autopilot"))
    elif "dkms" in module_families:
        checks.append(DoctorCheck("kernel_module_dkms", "warn", "DKMS packages are installed but dkms command was not found"))
    elif dkms_available:
        checks.append(DoctorCheck("kernel_module_dkms", "ok", "DKMS command is available; no DKMS module packages detected"))
    else:
        checks.append(DoctorCheck("kernel_module_dkms", "ok", "No DKMS module packages detected"))

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

    incident_config = resolve_incident_config(effective_env)
    monitor_state = incident_monitor_status(
        runner=runner,
        service_path=incident_service_path,
        maintenance_service_path=incident_maintenance_service_path,
        maintenance_timer_path=incident_maintenance_timer_path,
    )
    if incident_config.error:
        checks.append(DoctorCheck("incident_config", "error", incident_config.error))
    else:
        checks.append(DoctorCheck(
            "incident_assistant",
            "ok",
            "Incident Recovery Assistant is available",
            {
                "ai_review_enabled": incident_config.ai_enabled,
                "ai_evidence": incident_config.ai_evidence,
                "monitor_config_enabled": incident_config.monitor_enabled,
                "background_ai_enabled": incident_config.background_ai_enabled,
            },
        ))
        if incident_config.monitor_enabled and monitor_state["installed"] and monitor_state["enabled"] in {"enabled", "enabled-runtime", "linked"}:
            checks.append(DoctorCheck("incident_monitor", "ok", "Incident boot monitor is installed and enabled", monitor_state))
        elif incident_config.monitor_enabled and not monitor_state["installed"]:
            checks.append(DoctorCheck("incident_monitor", "warn", f"Incident monitor is enabled in config but {incident_service_path} is not installed", monitor_state))
        elif incident_config.monitor_enabled:
            checks.append(DoctorCheck("incident_monitor", "warn", "Incident monitor is enabled in config but systemd does not report it enabled", monitor_state))
        else:
            checks.append(DoctorCheck("incident_monitor", "warn", "Automatic previous-boot and weekly incident detection is disabled", monitor_state))
        maintenance_ready = bool(
            monitor_state.get("maintenance_installed")
            and monitor_state.get("maintenance_enabled") in {"enabled", "enabled-runtime", "linked"}
        )
        if incident_config.monitor_enabled and maintenance_ready:
            schedule_bits = []
            if monitor_state.get("maintenance_last_trigger"):
                schedule_bits.append(f"last trigger: {monitor_state['maintenance_last_trigger']}")
            if monitor_state.get("maintenance_next_run"):
                schedule_bits.append(f"next run: {monitor_state['maintenance_next_run']}")
            schedule_suffix = "; " + "; ".join(schedule_bits) if schedule_bits else ""
            checks.append(DoctorCheck(
                "incident_maintenance_timer",
                "ok",
                "Weekly incident maintenance timer is installed and enabled" + schedule_suffix,
                monitor_state,
            ))
        elif incident_config.monitor_enabled:
            checks.append(DoctorCheck(
                "incident_maintenance_timer",
                "warn",
                "Incident monitoring is enabled, but weekly maintenance is not fully installed and enabled",
                monitor_state,
            ))
        else:
            checks.append(DoctorCheck("incident_maintenance_timer", "warn", "Weekly incident maintenance is disabled"))

        _maintenance_state_path, maintenance_status_path = maintenance_paths(incident_system_root)
        maintenance_status = load_maintenance_status(maintenance_status_path)
        if incident_config.monitor_enabled and maintenance_status.get("overdue"):
            checks.append(DoctorCheck(
                "incident_maintenance_health",
                "warn",
                "Weekly incident maintenance is overdue or its last scan was incomplete",
                maintenance_status,
            ))
        elif incident_config.monitor_enabled and maintenance_status.get("last_success_usec"):
            checks.append(DoctorCheck(
                "incident_maintenance_health",
                "ok",
                "Weekly incident maintenance has a successful checkpoint",
                maintenance_status,
            ))
        elif incident_config.monitor_enabled:
            checks.append(DoctorCheck(
                "incident_maintenance_health",
                "warn",
                "Weekly incident maintenance has not completed its baseline scan",
                maintenance_status,
            ))
        else:
            checks.append(DoctorCheck("incident_maintenance_health", "ok", "Weekly incident maintenance health is inactive"))

        background_units = background_unit_status(runner=runner, unit_root=incident_background_unit_root)
        report_root = incident_user_root or user_incident_root(effective_env)
        background_state = load_private_json(background_state_path(report_root))
        background_result = load_private_json(background_result_path(report_root))
        raw_marker_retries = background_state.get("markers", {})
        marker_retries = raw_marker_retries.values() if isinstance(raw_marker_retries, Mapping) else []
        retry_times = [
            int(item.get("next_retry_usec") or 0)
            for item in marker_retries
            if isinstance(item, Mapping) and int(item.get("next_retry_usec") or 0) > 0
        ]
        provider_ready = bool(ai_config.ready and incident_config.ai_enabled)
        background_details = {
            "enabled": incident_config.background_ai_enabled,
            "provider_ready": provider_ready,
            "evidence_mode": incident_config.ai_evidence,
            "units": background_units,
            "last_status": background_state.get("last_status", "never"),
            "last_attempt_usec": int(background_state.get("last_attempt_usec") or 0),
            "last_success_usec": int(background_state.get("last_success_usec") or 0),
            "last_error": str(background_state.get("last_error") or "")[:500],
            "next_retry_usec": min(retry_times) if retry_times else 0,
            "last_prepared_repair_count": int(background_result.get("prepared_repair_count") or 0),
            "last_planner_status": str(background_result.get("planner_status") or "never"),
            "last_provider_requests": int(background_result.get("provider_requests") or 0),
            "last_completed_probe_count": int(background_result.get("completed_probe_count") or 0),
            "last_analysis_fingerprint_present": bool(background_result.get("analysis_fingerprint")),
            "last_plan_fingerprint_present": bool(background_result.get("repair_plan_fingerprint")),
        }
        timer_ready = bool(
            background_units.get("installed")
            and background_units.get("timer_enabled") in {"enabled", "enabled-runtime", "linked"}
            and background_units.get("timer_active") == "active"
        )
        if not incident_config.background_ai_enabled:
            checks.append(DoctorCheck(
                "incident_background_ai",
                "ok",
                "Background incident AI is disabled (separate opt-in)",
                background_details,
            ))
        elif provider_ready and timer_ready:
            checks.append(DoctorCheck(
                "incident_background_ai",
                "ok",
                "Background incident AI is provider-ready and its user timer is active",
                background_details,
            ))
        elif not provider_ready:
            checks.append(DoctorCheck(
                "incident_background_ai",
                "warn",
                "Background incident AI is enabled, but the incident AI provider or API key is not ready",
                background_details,
            ))
        else:
            checks.append(DoctorCheck(
                "incident_background_ai",
                "warn",
                "Background incident AI is enabled, but its user service and timer are not fully ready",
                background_details,
            ))

        auto_policy = read_auto_repair_policy(
            incident_auto_repair_policy_path,
            required_uid=incident_auto_repair_policy_uid,
        )
        _safe_state_path, safe_status_path, _safe_lock_path = safe_automation_paths(incident_system_root)
        safe_status = load_private_json(safe_status_path)
        auto_details = {
            "policy": auto_policy.policy,
            "policy_path": str(auto_policy.path),
            "service_path": str(incident_safe_service_path),
            "service_installed": incident_safe_service_path.is_file(),
            "last_state": safe_status.get("state", "never"),
            "last_attempt_usec": int(safe_status.get("last_attempt_usec") or 0),
            "last_success_usec": int(safe_status.get("last_success_usec") or 0),
            "last_action_count": int(safe_status.get("action_count") or 0),
        }
        if auto_policy.error:
            checks.append(DoctorCheck("incident_safe_autopilot", "error", auto_policy.error, auto_details))
        elif auto_policy.policy == "off":
            checks.append(DoctorCheck(
                "incident_safe_autopilot",
                "ok",
                "Incident Safe Autopilot is disabled (default)",
                auto_details,
            ))
        elif not incident_safe_service_path.is_file():
            checks.append(DoctorCheck(
                "incident_safe_autopilot",
                "warn",
                f"Incident Safe Autopilot is enabled, but {incident_safe_service_path} is not installed",
                auto_details,
            ))
        elif safe_status.get("state") == "failed":
            checks.append(DoctorCheck(
                "incident_safe_autopilot",
                "warn",
                "Incident Safe Autopilot is enabled, but its last reversible repair did not verify successfully",
                auto_details,
            ))
        else:
            checks.append(DoctorCheck(
                "incident_safe_autopilot",
                "ok",
                "Incident Safe Autopilot is ready for stale-lock and verified mirrorlist recovery",
                auto_details,
            ))

    if which("journalctl"):
        journal_probe = run_bounded_command(runner, ["journalctl", "--list-boots", "--no-pager"], max_chars=16000, timeout=15)
        journal_access = journal_probe.returncode == 0
        journal_status = "ok" if journal_root.exists() and journal_access else "warn"
        if not journal_access:
            journal_message = "journalctl is installed, but AuraScan could not read the boot journal with the current permissions"
        elif journal_root.exists():
            journal_message = "Persistent system journal storage is available and readable"
        else:
            journal_message = "journalctl is readable, but persistent journal storage was not detected; previous-boot evidence may be unavailable"
        checks.append(DoctorCheck("incident_journal", journal_status, journal_message, {"persistent_path": str(journal_root), "persistent": journal_root.exists(), "readable": journal_access}))
    else:
        checks.append(DoctorCheck("incident_journal", "warn", "journalctl is missing; system incident collection cannot run"))
    if which("coredumpctl"):
        coredump_probe = run_bounded_command(runner, ["coredumpctl", "--json=short", "--no-pager", "-n", "1", "list"], max_chars=16000, timeout=15)
        coredump_access = coredump_probe.returncode in {0, 1}
        checks.append(DoctorCheck(
            "incident_coredumps",
            "ok" if coredump_access else "warn",
            "coredumpctl is available and readable for application crash metadata" if coredump_access else "coredumpctl is installed, but application crash metadata is not readable",
            {"readable": coredump_access},
        ))
    else:
        checks.append(DoctorCheck("incident_coredumps", "warn", "coredumpctl is missing; application crash metadata will be unavailable"))
    if pstore_root.exists() and os.access(str(pstore_root), os.R_OK):
        checks.append(DoctorCheck("incident_pstore", "ok", f"Persistent kernel crash storage is readable at {pstore_root}"))
    elif pstore_root.exists():
        checks.append(DoctorCheck("incident_pstore", "warn", f"Persistent kernel crash storage exists at {pstore_root} but requires monitor/root access"))
    else:
        checks.append(DoctorCheck("incident_pstore", "ok", "No pstore filesystem is exposed; other incident sources remain available"))
    if incident_system_root.exists():
        checks.append(DoctorCheck("incident_storage", "ok", f"Incident system storage exists at {incident_system_root}"))
    elif not incident_config.error and incident_config.monitor_enabled:
        checks.append(DoctorCheck("incident_storage", "warn", f"Incident monitor storage is missing at {incident_system_root}"))
    else:
        checks.append(DoctorCheck("incident_storage", "ok", "Incident system storage will be created when the monitor is enabled"))

    repair_tools = [name for name in ("pacman", "systemctl", "dkms", "mkinitcpio", "dracut", "paccache", "pacman-key") if which(name)]
    checks.append(DoctorCheck(
        "incident_repair_tools",
        "ok" if "pacman" in repair_tools and "systemctl" in repair_tools else "warn",
        "Incident repair tools found: " + (", ".join(repair_tools) if repair_tools else "none"),
        {"found": repair_tools},
    ))
    guided_probe_tools = [name for name in ("pacman", "pacman-key", "systemctl", "dkms", "mkinitcpio", "dracut", "paccache") if which(name)]
    guided_ready = "pacman" in guided_probe_tools and "systemctl" in guided_probe_tools
    checks.append(DoctorCheck(
        "incident_ai_repair_planner",
        "ok" if guided_ready else "warn",
        "AI-guided repair probes are ready for two-pass incident analysis"
        if guided_ready else
        "AI-guided repair probes have limited coverage because pacman or systemctl is unavailable",
        {
            "two_pass_enabled_with_incident_ai": True,
            "background_prepare_only": True,
            "probe_tools": guided_probe_tools,
            "maximum_provider_requests": 2,
        },
    ))
    hardware_tools = hardware_health_doctor_status(which=which)
    hardware_basic = bool(
        hardware_tools.get("cpu_inventory")
        and hardware_tools.get("memory_inventory")
        and hardware_tools.get("dmi_inventory")
    )
    hardware_optional = bool(
        hardware_tools.get("hwmon")
        and hardware_tools.get("lspci")
        and hardware_tools.get("fwupdmgr")
    )
    if hardware_basic and hardware_optional:
        hardware_status = "ok"
        hardware_message = (
            "Hardware follow-up probes are ready for inventory, cooling, driver, and firmware checks"
        )
    elif hardware_basic:
        hardware_status = "warn"
        hardware_message = (
            "Hardware inventory is available, but cooling, GPU naming, or firmware-update "
            "coverage is limited by optional tools or kernel sensor support"
        )
    else:
        hardware_status = "warn"
        hardware_message = (
            "Hardware follow-up context is limited because CPU, memory, or DMI inventory "
            "is not readable"
        )
    checks.append(DoctorCheck(
        "hardware_followup",
        hardware_status,
        hardware_message,
        hardware_tools,
    ))

    recovery_config = resolve_recovery_config(effective_env)
    try:
        recovery_state = recovery_status(root=recovery_root, runner=runner, which=which)
    except Exception as exc:
        recovery_state = {"error": str(exc), "policy": {}, "image": {}, "tools": {}}
    recovery_policy = recovery_state.get("policy", {}) if isinstance(recovery_state.get("policy"), Mapping) else {}
    recovery_image = recovery_state.get("image", {}) if isinstance(recovery_state.get("image"), Mapping) else {}
    recovery_tools = recovery_state.get("tools", {}) if isinstance(recovery_state.get("tools"), Mapping) else {}
    recovery_installation = recovery_state.get("installation", {}) if isinstance(recovery_state.get("installation"), Mapping) else {}
    recovery_enabled = bool(recovery_policy.get("enabled"))
    recovery_policy_error = str(recovery_policy.get("error") or "")
    recovery_access_limited = bool(
        recovery_policy_error
        and "recovery policy could not be read" in recovery_policy_error.lower()
        and ("permission denied" in recovery_policy_error.lower() or "errno 13" in recovery_policy_error.lower())
    )
    if recovery_config.error:
        checks.append(DoctorCheck("recovery_config", "error", recovery_config.error))
    elif recovery_access_limited:
        checks.append(DoctorCheck(
            "recovery_config",
            "warn",
            "Recovery system policy is root-only; run sudo aurascan recovery --status for installed image details",
            {"status_requires_root": True},
        ))
    elif recovery_policy_error:
        checks.append(DoctorCheck("recovery_config", "error", recovery_policy_error, dict(recovery_policy)))
    else:
        checks.append(DoctorCheck(
            "recovery_config",
            "ok" if recovery_enabled else "warn",
            "AuraScan Recovery is enabled" if recovery_enabled else "AuraScan Recovery is optional and not installed",
            {"user": recovery_config.to_dict(), "system_policy": dict(recovery_policy)},
        ))
    image_ready = bool(recovery_image.get("installed") and recovery_image.get("valid_pe") and not recovery_image.get("errors"))
    if recovery_access_limited:
        checks.append(DoctorCheck(
            "recovery_image",
            "warn",
            "Recovery image status requires root access; AuraScan made no installation-state inference",
            {"status_requires_root": True},
        ))
    elif recovery_enabled and image_ready and not recovery_image.get("stale"):
        checks.append(DoctorCheck("recovery_image", "ok", f"Recovery image {recovery_image.get('version') or 'unknown'} is installed and current", dict(recovery_image)))
    elif recovery_enabled and recovery_image.get("stale"):
        checks.append(DoctorCheck("recovery_image", "warn", "Recovery image is stale and should be refreshed", dict(recovery_image)))
    elif recovery_enabled:
        checks.append(DoctorCheck("recovery_image", "error", "Recovery is enabled but its UKI is missing or invalid", dict(recovery_image)))
    else:
        checks.append(DoctorCheck("recovery_image", "ok", "No internal recovery image is expected while recovery is disabled", dict(recovery_image)))
    bootloader = recovery_image.get("bootloader", {}) if isinstance(recovery_image.get("bootloader"), Mapping) else {}
    if recovery_access_limited:
        checks.append(DoctorCheck(
            "recovery_bootloader",
            "warn",
            "Recovery bootloader status requires root access",
            {"status_requires_root": True},
        ))
    else:
        checks.append(DoctorCheck(
            "recovery_bootloader",
            "ok" if bootloader.get("installed") else "warn",
            f"Recovery bootloader adapter: {bootloader.get('name', 'Unknown')}" if bootloader.get("installed") else "No supported recovery bootloader adapter was detected",
            dict(bootloader),
        ))
    secure_boot = str(recovery_image.get("secure_boot") or "unknown")
    signed = bool(recovery_image.get("signed"))
    secure_ok = secure_boot != "enabled" or signed or not recovery_enabled
    checks.append(DoctorCheck(
        "recovery_secure_boot",
        "ok" if secure_ok else "error",
        "Recovery Secure Boot signing is ready" if secure_boot == "enabled" and signed else f"Recovery Secure Boot state: {secure_boot}",
        {"secure_boot": secure_boot, "signed": signed},
    ))
    esp_space_ready = bool(recovery_installation.get("esp_space_ready"))
    checks.append(DoctorCheck(
        "recovery_esp",
        "ok" if esp_space_ready else "warn",
        "Recovery ESP has the minimum free-space reserve" if esp_space_ready else "Recovery ESP space or mount readiness could not be proven",
        {
            "path": recovery_installation.get("esp_path"),
            "free_bytes": recovery_installation.get("esp_free_bytes"),
            "minimum_free_bytes": recovery_installation.get("minimum_esp_free_bytes"),
            "installation_errors": list(recovery_installation.get("errors", [])) if isinstance(recovery_installation.get("errors"), list) else [],
        },
    ))
    build_ready = bool(recovery_tools.get("mkosi") and recovery_tools.get("ukify") and recovery_state.get("profile_installed"))
    checks.append(DoctorCheck(
        "recovery_build_tools",
        "ok" if build_ready else "warn",
        "Recovery UKI build tools and profile are ready" if build_ready else "Recovery UKI build needs mkosi, ukify, and the packaged profile",
        {"tools": dict(recovery_tools), "profile_installed": bool(recovery_state.get("profile_installed"))},
    ))
    network_ready = bool(recovery_tools.get("NetworkManager") and recovery_tools.get("nmcli"))
    storage_ready = all(recovery_tools.get(name) for name in ("cryptsetup", "lvm", "mdadm"))
    checks.append(DoctorCheck(
        "recovery_runtime_tools",
        "ok" if network_ready and storage_ready else "warn",
        "Recovery networking and encrypted/storage discovery tools are ready" if network_ready and storage_ready else "Recovery runtime has partial networking or encrypted/storage coverage",
        {"network_ready": network_ready, "storage_ready": storage_ready, "tools": dict(recovery_tools)},
    ))
    recovery_provider_ready = bool(not ai_config.error and ai_config.authentication_ready)
    recovery_ai_ready = bool(recovery_config.ai_enabled and recovery_provider_ready)
    checks.append(DoctorCheck(
        "recovery_ai",
        "ok" if recovery_ai_ready else "warn",
        "Recovery AI consent and provider are ready" if recovery_ai_ready else "Recovery AI is separately disabled or its provider is not ready; offline recovery remains available",
        {
            "enabled": recovery_config.ai_enabled,
            "provider": ai_config.provider,
            "provider_ready": recovery_provider_ready,
            "key_present": ai_config.api_key_present,
            "maximum_provider_requests": 2,
        },
    ))
    refresh_ready = bool(recovery_state.get("refresh_hook_installed"))
    if recovery_access_limited and refresh_ready:
        checks.append(DoctorCheck(
            "recovery_refresh",
            "warn",
            "Recovery refresh hook is installed; last refresh status requires root access",
            {"installed": True, "status_requires_root": True},
        ))
    else:
        checks.append(DoctorCheck(
            "recovery_refresh",
            "ok" if (not recovery_enabled or refresh_ready) else "warn",
            "Recovery refresh hook is installed" if refresh_ready else "Recovery refresh hook is missing",
            {"installed": refresh_ready, "last_status": recovery_policy.get("last_refresh_status"), "last_error": recovery_policy.get("last_refresh_error")},
        ))
    recovery_iso = recovery_state.get("iso_manifest", {}) if isinstance(recovery_state.get("iso_manifest"), Mapping) else {}
    iso_digest = str(recovery_iso.get("sha256") or "").lower()
    iso_ready = bool(
        re.fullmatch(r"[0-9a-f]{64}", iso_digest)
        and str(recovery_iso.get("url") or "").startswith("https://github.com/crizzler/AuraScan/releases/download/")
    )
    checks.append(DoctorCheck(
        "recovery_iso",
        "ok" if iso_ready else "warn",
        "Recovery USB ISO manifest has a pinned SHA-256 digest" if iso_ready else "Recovery USB ISO digest is not finalized for this release",
        {"version": recovery_iso.get("version"), "digest_pinned": iso_ready},
    ))
    last_recovery = recovery_state.get("last_recovery", {}) if isinstance(recovery_state.get("last_recovery"), Mapping) else {}
    repair_statuses = last_recovery.get("repair_statuses", []) if isinstance(last_recovery.get("repair_statuses"), list) else []
    last_failed = any(item in {"failed", "refused", "rolled_back"} for item in repair_statuses)
    if recovery_access_limited:
        checks.append(DoctorCheck(
            "recovery_last_result",
            "warn",
            "The private last-recovery result requires root access",
            {"status_requires_root": True},
        ))
    else:
        checks.append(DoctorCheck(
            "recovery_last_result",
            "warn" if last_failed or last_recovery.get("error") else "ok",
            "The last recovery run retained failed or refused actions" if last_failed else "No failed private recovery result is recorded",
            dict(last_recovery),
        ))

    updater_status = build_updater_status(
        env=effective_env,
        paths=updater_desktop_paths(config_home=updater_config_home, data_home=updater_data_home),
        which=which,
        qt_binding_finder=qt_binding_finder,
    )
    if updater_status.config.error:
        checks.append(DoctorCheck("updater_tray", "error", updater_status.config.error))
    elif updater_status.config.tray_enabled:
        checks.append(DoctorCheck(
            "updater_tray",
            "ok",
            "AuraScan Updater tray icon is enabled",
            {"enabled": True, "autostart_enabled": updater_status.config.autostart_enabled},
        ))
    else:
        checks.append(DoctorCheck("updater_tray", "warn", "AuraScan Updater tray icon is disabled", {"enabled": False}))
    if updater_status.qt_binding:
        checks.append(DoctorCheck("updater_qt_binding", "ok", f"Updater Qt binding found: {updater_status.qt_binding}"))
    else:
        checks.append(DoctorCheck("updater_qt_binding", "warn", "PyQt6/PySide6 not found; AuraScan Updater tray applet cannot start"))
    if updater_status.terminal:
        checks.append(DoctorCheck("updater_terminal", "ok", f"Updater terminal found: {updater_status.terminal}", {"path": updater_status.terminal_path}))
    else:
        checks.append(DoctorCheck("updater_terminal", "warn", "No supported terminal found for AuraScan Updater"))
    if updater_status.autostart_installed:
        checks.append(DoctorCheck("updater_autostart", "ok", f"Updater autostart installed at {updater_status.paths.autostart_desktop}"))
    elif updater_status.config.autostart_enabled:
        checks.append(DoctorCheck("updater_autostart", "warn", f"Updater autostart is enabled in config but missing at {updater_status.paths.autostart_desktop}"))
    else:
        checks.append(DoctorCheck("updater_autostart", "warn", "Updater autostart is not installed", {"installed": False}))

    if not incident_config.error and incident_config.monitor_enabled:
        if updater_status.config.tray_enabled and updater_status.autostart_installed and updater_status.qt_binding:
            checks.append(DoctorCheck("incident_tray_notification", "ok", "Tray notifications are ready for newly recorded incidents"))
        else:
            checks.append(DoctorCheck("incident_tray_notification", "warn", "Incident monitoring is enabled, but the AuraScan tray is not fully ready to show automatic crash notifications"))
    else:
        checks.append(DoctorCheck("incident_tray_notification", "ok", "Incident tray notifications are inactive because the boot monitor is disabled"))

    campaign_status = bundled_campaign_doctor_status()
    if campaign_status.get("ready"):
        checks.append(DoctorCheck(
            "security_campaign_intel",
            "ok",
            f"Bundled AUR campaign intelligence is validated ({campaign_status.get('package_count')} package names)",
            campaign_status,
        ))
    else:
        checks.append(DoctorCheck(
            "security_campaign_intel",
            "error",
            f"Bundled AUR campaign intelligence is invalid: {campaign_status.get('error')}",
            campaign_status,
        ))
    arch_audit_path = which("arch-audit")
    checks.append(DoctorCheck(
        "security_arch_audit",
        "ok" if arch_audit_path else "warn",
        f"arch-audit found at {arch_audit_path}" if arch_audit_path else "arch-audit is not installed; official-package CVE checks are optional and will be skipped",
        {"path": arch_audit_path, "scope": "official Arch Security Team advisories"},
    ))

    for tool in ("clamscan", "bsdtar", "gpg", "makepkg", "pacman", "vercmp"):
        found = which(tool)
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


def _prompt_agent_access(input_func: Callable[[str], str], default: str, stdout) -> str:
    choices = list(AGENT_ACCESS_VALUES)
    default = default if default in choices else "guarded"
    descriptions = {
        "guarded": "AuraScan-owned probes and verified repairs; no model command field",
        "user-shell": "compatibility profile for allowlisted local read-only diagnostics",
        "root-shell": "policy-gated diagnostics plus constrained /usr/bin/pacman repairs",
    }
    print(
        "Policy-Gated Repair Agent access defaults (user-shell/root-shell are compatibility profile names):",
        file=stdout,
    )
    for index, value in enumerate(choices, start=1):
        marker = " default" if value == default else ""
        print(f"  {index}. {value}{marker}: {descriptions[value]}", file=stdout)
    while True:
        answer = input_func(f"Repair Agent access [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("Please choose guarded, user-shell, or root-shell.", file=stdout)


def _prompt_agent_approval(input_func: Callable[[str], str], default: str, stdout) -> str:
    choices = list(AGENT_APPROVAL_VALUES)
    default = default if default in choices else "each-command"
    print(
        "Policy-Gated Repair Agent command approval defaults (command-enabled profiles enforce each-command):",
        file=stdout,
    )
    for index, value in enumerate(choices, start=1):
        marker = " default" if value == default else ""
        print(f"  {index}. {value}{marker}", file=stdout)
    while True:
        answer = input_func(f"Repair Agent approval [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("Please choose each-command, whole-plan, or session.", file=stdout)


def _prompt_agent_output(input_func: Callable[[str], str], default: str, stdout) -> str:
    choices = list(AGENT_OUTPUT_VALUES)
    default = default if default in choices else "redacted"
    print("Repair Agent terminal-output sharing defaults:", file=stdout)
    for index, value in enumerate(choices, start=1):
        marker = " default" if value == default else ""
        print(f"  {index}. {value}{marker}", file=stdout)
    while True:
        answer = input_func(f"Repair Agent output sharing [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("Please choose redacted or full.", file=stdout)


def _prompt_recovery_wifi_profiles(input_func: Callable[[str], str], default: str, stdout) -> str:
    choices = ["auto", "ask", "never"]
    default = default if default in choices else "ask"
    print("Recovery saved Wi-Fi profile permission:", file=stdout)
    for index, policy in enumerate(choices, start=1):
        marker = " default" if policy == default else ""
        print(f"  {index}. {policy}{marker}", file=stdout)
    while True:
        answer = input_func(f"Recovery Wi-Fi profiles [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("Please choose auto, ask, or never.", file=stdout)


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


def _doctor_command_lines(runner: Callable, cmd: List[str]) -> List[str]:
    try:
        result = runner(list(cmd), capture_output=True, text=True, check=False)
    except OSError:
        return []
    if int(getattr(result, "returncode", 0)) != 0:
        return []
    return [line.strip() for line in str(getattr(result, "stdout", "") or "").splitlines() if line.strip()]


def _check_ai_connectivity(env: Mapping[str, str], *, urlopen: Optional[Callable] = None) -> DoctorCheck:
    config = resolve_ai_config(env)
    if config.error:
        return DoctorCheck("ai_connectivity", "error", f"AI connectivity check skipped: {config.error}")
    if not config.enabled:
        return DoctorCheck("ai_connectivity", "warn", "AI connectivity check skipped because AI is disabled")
    if not config.authentication_ready:
        return DoctorCheck("ai_connectivity", "error", f"AI connectivity check skipped: {config.key_env} is missing")
    try:
        text = call_ai_provider(config, connectivity_prompt(), timeout=15, urlopen=urlopen)
    except Exception as exc:
        return DoctorCheck(
            "ai_connectivity",
            "error",
            "AI connectivity failed: " + safe_provider_error_detail(exc),
        )
    if text.startswith("BENIGN:"):
        return DoctorCheck("ai_connectivity", "ok", "AI provider connectivity check passed")
    return DoctorCheck("ai_connectivity", "warn", "AI provider responded, but not with AuraScan's expected test format")


def _check_executable(path: Path) -> DoctorCheck:
    if path.exists():
        return DoctorCheck("installed_executable", "ok", f"Installed executable found at {path}")
    return DoctorCheck("installed_executable", "warn", f"{path} not found; pacman hook install will be refused until AuraScan is installed system-wide")


def _hook_checks(*, local_hook_path: Path = LOCAL_HOOK_PATH, packaged_hook_path: Path = PACKAGED_HOOK_PATH) -> List[DoctorCheck]:
    checks = []
    local_exists = local_hook_path.exists()
    packaged_exists = packaged_hook_path.exists()
    local_safe = local_exists and is_release_safe_hook_template(local_hook_path)
    packaged_safe = packaged_exists and is_release_safe_hook_template(packaged_hook_path)

    if local_exists:
        if local_safe:
            checks.append(DoctorCheck("local_pacman_hook", "ok", f"{local_hook_path} is installed and release-safe"))
        else:
            checks.append(DoctorCheck("local_pacman_hook", "error", f"{local_hook_path} is installed but does not match AuraScan release-safety rules"))
    elif packaged_safe:
        checks.append(DoctorCheck("local_pacman_hook", "ok", f"No local pacman hook override at {local_hook_path}; packaged hook is release-safe"))
    else:
        checks.append(DoctorCheck("local_pacman_hook", "warn", f"{local_hook_path} is not installed"))

    if packaged_exists:
        if packaged_safe:
            checks.append(DoctorCheck("packaged_pacman_hook", "ok", f"{packaged_hook_path} is installed and release-safe"))
        else:
            checks.append(DoctorCheck("packaged_pacman_hook", "error", f"{packaged_hook_path} is installed but does not match AuraScan release-safety rules"))
    elif local_safe:
        checks.append(DoctorCheck("packaged_pacman_hook", "ok", f"{packaged_hook_path} is not installed; local hook is release-safe"))
    else:
        checks.append(DoctorCheck("packaged_pacman_hook", "warn", f"{packaged_hook_path} is not installed"))
    return checks


def _format_check_line(check: DoctorCheck) -> str:
    label = check.status.upper()
    return f"[{label}] {check.message}"
