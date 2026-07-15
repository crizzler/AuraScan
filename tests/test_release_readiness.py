from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_pyproject_console_scripts_are_registered():
    data = tomllib.loads(read_text("pyproject.toml"))

    scripts = data["project"]["scripts"]
    assert data["project"]["version"] == "0.4.0"
    assert scripts["aurascan"] == "aurascan.cli:main"
    assert scripts["aurascan-makepkg"] == "aurascan.makepkg_wrapper:main"
    assert data["project"]["requires-python"] == ">=3.8"
    assert data["project"]["dependencies"] == []
    assert data["project"]["license"] == "MIT"
    assert data["project"]["license-files"] == ["LICENSE"]
    assert "pytest>=8.0" in data["project"]["optional-dependencies"]["test"]
    assert "PyQt6>=6.0" in data["project"]["optional-dependencies"]["updater"]
    assert data["tool"]["setuptools"]["package-data"]["aurascan"] == ["assets/*"]


def test_entry_point_targets_import():
    from aurascan.cli import main as cli_main
    from aurascan.__main__ import main as module_main
    from aurascan.core.kernel_module_autopilot import build_kernel_module_check
    from aurascan.core.incidents import run_incidents
    from aurascan.makepkg_wrapper import main as wrapper_main
    from aurascan.core.updater_tray import run_updater

    assert callable(cli_main)
    assert callable(module_main)
    assert callable(build_kernel_module_check)
    assert callable(run_incidents)
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
        "python -m pip install -e \".[test]\" && python -m aurascan init",
        "not currently published to official distribution repositories",
        "public arch/aur package recipe lives under `packaging/arch/`",
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
        "the monitor has no network access",
        "makes no background ai requests",
        "ai cannot generate commands",
        "does not automate filesystem repair",
        "aurascan_incident_ai_evidence",
    ]
    for phrase in required_phrases:
        assert phrase in readme


def test_license_is_mit_for_public_release():
    license_text = read_text("LICENSE")

    assert license_text.startswith("MIT License")
    assert "Copyright (c) 2026 Arawn" in license_text
    assert "THE SOFTWARE IS PROVIDED \"AS IS\"" in license_text


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
        "Incident monitor is installed disabled and has no network access.",
        "Incident repair actions are allowlisted and freshly revalidated as root.",
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
