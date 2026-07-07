from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_pyproject_console_scripts_are_registered():
    data = tomllib.loads(read_text("pyproject.toml"))

    scripts = data["project"]["scripts"]
    assert scripts["aurascan"] == "aurascan.cli:main"
    assert scripts["aurascan-makepkg"] == "aurascan.makepkg_wrapper:main"
    assert data["project"]["requires-python"] == ">=3.8"
    assert data["project"]["dependencies"] == []
    assert data["project"]["license"]["text"] == "MIT"
    assert "License :: OSI Approved :: MIT License" in data["project"]["classifiers"]
    assert "pytest>=8.0" in data["project"]["optional-dependencies"]["test"]


def test_entry_point_targets_import():
    from aurascan.cli import main as cli_main
    from aurascan.makepkg_wrapper import main as wrapper_main

    assert callable(cli_main)
    assert callable(wrapper_main)


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
        "aurascan_ai_enabled",
        "provider-specific keys",
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
