from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.8 CI job
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_pyproject_console_scripts_are_registered():
    data = tomllib.loads(read_text("pyproject.toml"))

    scripts = data["project"]["scripts"]
    assert data["project"]["version"] == "0.9.1"
    assert scripts["aurascan"] == "aurascan.cli:main"
    assert scripts["aurascan-makepkg"] == "aurascan.makepkg_wrapper:main"
    assert data["project"]["requires-python"] == ">=3.8"
    assert data["project"]["dependencies"] == []
    assert data["build-system"]["requires"] == ["setuptools>=61.0"]
    assert data["project"]["license"] == {"file": "LICENSE"}
    assert "pytest>=8.0" in data["project"]["optional-dependencies"]["test"]
    assert "tomli>=1.1.0; python_version < '3.11'" in data["project"]["optional-dependencies"]["test"]
    assert "PyQt6>=6.0" in data["project"]["optional-dependencies"]["updater"]
    assert data["tool"]["setuptools"]["package-data"]["aurascan"] == ["assets/*"]


def test_entry_point_targets_import():
    from aurascan.cli import main as cli_main
    from aurascan.__main__ import main as module_main
    from aurascan.core.agent import run_agent
    from aurascan.core.followup import run_ask
    from aurascan.core.hardware_health import collect_hardware_health
    from aurascan.core.kernel_module_autopilot import build_kernel_module_check
    from aurascan.core.incidents import run_incidents
    from aurascan.core.instruction_cli import run_instruction_audit
    from aurascan.makepkg_wrapper import main as wrapper_main
    from aurascan.core.updater_tray import run_updater

    assert callable(cli_main)
    assert callable(module_main)
    assert callable(run_agent)
    assert callable(run_ask)
    assert callable(collect_hardware_health)
    assert callable(build_kernel_module_check)
    assert callable(run_incidents)
    assert callable(run_instruction_audit)
    assert callable(wrapper_main)
    assert callable(run_updater)


def test_readme_contains_release_safety_boundaries():
    readme = read_text("README.md").lower()

    required_phrases = [
        "does not prove that a package is safe",
        "a clean clamav result",
        "a valid source signature is not a guarantee",
        "default scans do not download declared sources",
        "default scan context is `unknown`",
        "--deep-static is explicit",
        "hard blockers cannot be accepted",
        "new-only is weaker protection",
        "\"no new dependencies\" is not enough",
        "--scan-context auto",
        "metadata-only tuning is opt-in",
        "aurascan init",
        "aurascan doctor",
        "python -m aurascan init",
        "python -m aurascan doctor",
        "published as [`aurascan`](https://aur.archlinux.org/packages/aurascan)",
        "paru -s aurascan",
        "yay -s aurascan",
        "git clone https://aur.archlinux.org/aurascan.git",
        "part of arch linux's official binary repositories",
        "source-tree reference recipe remains under `packaging/arch/`",
        "canonical public package history used by aur clients",
        "makepkg -si",
        "does not auto-run the wizard",
        "aurascan_ai_enabled",
        "provider-specific keys",
        "kernel/module autopilot is enabled by default",
        "aurascan_kernel_module_autopilot_enabled",
        "| manjaro | supported with caveats |",
        "gnome is fully supported for cli workflows",
        "kde plasma on wayland or x11 is the best-supported",
        "aurascan incidents --dry-run",
        "the optional root monitor is installed disabled",
        "the root collectors have no network access",
        "background ai is a second, per-user opt-in",
        "safe autopilot defaults to `off`",
        "it cannot run `sudo`",
        "ai cannot generate commands",
        "does not automate filesystem repair",
        "aurascan_incident_ai_evidence",
        "aurascan ask --latest",
        "eight questions and twelve provider requests",
        "questions and ai answers stay in memory",
        "parent `--yes` flags never authorize follow-up actions",
        "aurascan agent --latest",
        "ai cannot generate commands in guarded mode",
        "grant ai full root control",
        "user-authorized remote code execution",
        "aurascan_agent_access",
        "/etc/aurascan/agent.conf",
        "share full terminal output",
        "continue without rollback",
        "foreground-only",
        "hardware, memory pressure, temperatures, cooling, drivers",
        "serial numbers",
        "raw firmware tables",
    ]
    for phrase in required_phrases:
        assert phrase in readme


def test_license_is_mit_for_public_release():
    license_text = read_text("LICENSE")

    assert license_text.startswith("MIT License")
    assert "Copyright (c) 2026 Arawn" in license_text
    assert "THE SOFTWARE IS PROVIDED \"AS IS\"" in license_text


def test_privacy_document_covers_full_control_agent_boundaries():
    privacy = read_text("docs/PRIVACY.md").lower()

    required = [
        "foreground full-control repair agent",
        "grant ai full root control",
        "share full terminal output",
        "continue without rollback",
        "/run/aurascan-agent/",
        "~/.local/state/aurascan/agent/",
        "/var/lib/aurascan/agent/",
        "user-authorized remote code execution",
        "can defeat these software boundaries",
        "hardware-related questions can trigger a foreground read-only hardware probe",
        "does not read or transmit system serial numbers",
    ]
    for phrase in required:
        assert phrase in privacy


def test_instruction_guard_v090_documentation_contract():
    def normalized(relative: str) -> str:
        return " ".join(read_text(relative).lower().split())

    readme = normalized("README.md")
    privacy = normalized("docs/PRIVACY.md")
    checklist = normalized("docs/RELEASE_CHECKLIST.md")
    release = normalized("docs/releases/v0.9.0.md")

    readme_phrases = [
        "the opt-in agent instruction guard",
        "the monitor is installed disabled",
        "service runs after login and every five minutes with network access disabled",
        "a second, separately enabled user timer",
        "suspicious first-seen files alert immediately",
        "clean first-seen files enter one unreviewed inventory",
        "--all-markdown` extends content analysis",
        "not added to the integrity baseline",
        "disable only an unchanged, user-owned, standalone regular instruction file",
        "restore refuses changed or unsafe state",
        "a generic review prompt, never a path, snippet, username, credential, or ai text",
        "$xdg_state_home/aurascan/instruction-guard/",
        "private permissions",
        "same-user security boundary",
        "root malware can disable or deceive the monitor entirely",
        "does not preflight pasted commands or download links",
        "fanotify interception",
        "there is no automatic quarantine",
    ]
    for phrase in readme_phrases:
        assert phrase in readme

    privacy_phrases = [
        "an opt-in, unprivileged scanner",
        "all supported ai credentials removed from its environment",
        "optional `all-markdown` mode applies content rules",
        "does not baseline their integrity",
        "$xdg_state_home/aurascan/instruction-guard/",
        "with `0700` directories and `0600` files",
        "a generic severity, count, and request to review",
        "instruction guard ai is a second, independent opt-in",
        "confirmed disable is not quarantine",
        "returns the file to unreviewed status rather than trusting it",
        "does not preflight pasted commands or download links",
        "same-uid malware can read or alter user files",
        "root malware can disable or deceive the monitor",
    ]
    for phrase in privacy_phrases:
        assert phrase in privacy

    checklist_phrases = [
        "all-markdown mode performs content analysis only",
        "content risk and integrity state remain separate",
        "instruction guard approvals bind exact content to machine identity and uid",
        "instruction guard alert output and notifications contain no paths",
        "complete exact atomic disable/receipt/restore round trips",
        "instruction guard does not automatically quarantine a file",
        "offline instruction guard user service has no network or ai credentials",
        "instruction guard ai has a separate opt-in",
        "monitor and ai timers default to disabled",
        "pasted-command/link preflight, privileged fanotify/process interception",
        "a boundary against same-uid/root malware",
    ]
    for phrase in checklist_phrases:
        assert phrase in checklist

    release_phrases = [
        "# aurascan v0.9.0",
        "released on 2026-08-29",
        "instruction_guard_report/1.0",
        "rule version 1.0",
        "existing package-scanner rule version is unchanged",
        "application and arch/aur package advance to v0.9.0",
        "periodic detection, not pasted-command or link preflight",
        "privileged fanotify/process interception, or automatic quarantine",
    ]
    for phrase in release_phrases:
        assert phrase in release


def test_instruction_guard_tray_v091_release_contract():
    release = " ".join(read_text("docs/releases/v0.9.1.md").lower().split())
    unreleased = " ".join(
        read_text("docs/releases/unreleased.md").lower().split()
    )

    required = [
        "# aurascan v0.9.1",
        "released on 2026-08-30",
        "instruction guard background scan",
        "instruction guard ai analysis",
        "run asynchronously without a shell",
        "bounded combined child stdout and stderr to 64 kib",
        "tray quit action is disabled",
        "real pyqt6 and pyside6 event-loop stress tests",
        "arch/aur package advance to v0.9.1",
        "report schema and rule version remain 1.0",
        "package-scanner rule version is unchanged",
    ]
    for phrase in required:
        assert phrase in release
    assert "changes after v0.9.1 will be recorded here" in unreleased


def test_release_checklist_references_required_validation_and_safety_items():
    checklist = read_text("docs/RELEASE_CHECKLIST.md")

    required_phrases = [
        "python -m compileall aurascan tests tools",
        ".venv/bin/python -m pytest -q",
        "tools/audit_presenter_coverage.py --strict-medium",
        "No generic force flag or hard-blocker bypass exists.",
        "Default fast scan does not download declared sources.",
        "Smart fast path requires verified update context",
        "Live AUR sampling is not part of normal pytest.",
        "MIT license is present.",
        "No generated local artifacts are staged or committed.",
        "Incident root collectors are installed disabled, have no network access",
        "Background incident AI has a separate per-user opt-in",
        "Safe Autopilot defaults to `off`",
        "Incident repair actions are allowlisted and freshly revalidated as root.",
        "Follow-up contexts are private, fingerprinted, redacted before persistence",
        "Follow-up AI accepts only known fact, probe, and action IDs",
        "Repair Agent defaults to `guarded`",
        "Root-shell also requires a safe root-owned policy",
        "user-authorized remote code execution",
        "Hardware-aware follow-up runs only in an opted-in foreground AI workflow",
    ]
    for phrase in required_phrases:
        assert phrase in checklist


def test_gitignore_excludes_release_local_artifacts():
    ignore = read_text(".gitignore").splitlines()

    required_patterns = [
        ".venv/",
        "__pycache__/",
        "*.py[cod]",
        ".pytest_cache/",
        "dist/",
        "build/",
        ".build/",
        "*.egg-info/",
        "packaging/arch/pkg/",
        "packaging/arch/src/",
        "packaging/arch/*.pkg.tar.*",
        "packaging/arch/*.tar.gz",
        "*.db",
        "*.sqlite",
        "*.asc",
        "*.sig",
        "tools/reports/*",
        "!tools/reports/README.md",
        "/PKGBUILD.*",
        "/test_pkgbuild*",
    ]
    for pattern in required_patterns:
        assert pattern in ignore


def test_generated_report_hygiene_is_documented_and_ignored_by_default():
    ignore = read_text("tools/reports/.gitignore").splitlines()
    readme = read_text("tools/reports/README.md").lower()

    assert "*" in ignore
    assert "!README.md" in ignore
    assert "generated `.json` and `.md` reports are ignored by default" in readme
    assert "must not run makepkg" in readme
    assert "must not download declared sources" in readme
    assert "must not run gpg" in readme


def test_live_tuning_package_list_is_large_but_not_a_pytest_fixture():
    package_list = ROOT / "tools" / "package_lists" / "aur-warning-tune-mixed.txt"
    lines = package_list.read_text(encoding="utf-8").splitlines()
    packages = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

    assert 150 <= len(packages) <= 200
    assert "google-chrome" in packages
    assert "mongodb-bin" in packages
    assert "neovim-git" in packages
    assert "ttf-ms-fonts" in packages
    assert "tests" not in package_list.parts
