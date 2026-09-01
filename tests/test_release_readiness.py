import json
import os
import re
from datetime import date
from pathlib import Path

from aurascan.core.models import Severity
from aurascan.core.rule_metadata import get_rule_metadata

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.8 CI job
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_current_release_recovery_manifest_policy_is_versioned_and_fresh():
    version = tomllib.loads(read_text("pyproject.toml"))["project"]["version"]
    manifest = json.loads(read_text("aurascan/assets/aurascan-recovery-iso.json"))
    release = read_text(f"docs/releases/v{version}.md")
    match = re.search(r"^Released on ([0-9]{4}-[0-9]{2}-[0-9]{2})\.$", release, re.MULTILINE)

    assert match is not None
    application_date = date.fromisoformat(match.group(1))
    image_date = date.fromisoformat(manifest["released_at"])
    image_release = read_text(f"docs/releases/v{manifest['version']}.md")
    image_release_dates = re.findall(
        r"^Released on ([0-9]{4}-[0-9]{2}-[0-9]{2})\.$",
        image_release,
        re.MULTILINE,
    )
    assert image_release_dates == [manifest["released_at"]]
    assert manifest["application_version"] == version
    assert 0 <= (application_date - image_date).days <= 90
    assert manifest["release_disposition"] in {"recovery-bearing", "package-only"}
    if manifest["release_disposition"] == "recovery-bearing":
        assert manifest["version"] == version
    else:
        assert manifest["status"] == "release-ready"
        assert tuple(map(int, manifest["version"].split("."))) < tuple(
            map(int, version.split("."))
        )


def test_pyproject_console_scripts_are_registered():
    data = tomllib.loads(read_text("pyproject.toml"))

    scripts = data["project"]["scripts"]
    assert data["project"]["version"] == "0.10.3"
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
        "policy-gated repair agent",
        "grant ai root repair commands",
        "absolute read-only diagnostics",
        "constrained exact `/usr/bin/pacman`",
        "remote acquisition, arbitrary executables",
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
    assert "grant ai full root control" not in readme
    assert "user-authorized remote code execution" not in readme


def test_license_is_mit_for_public_release():
    license_text = read_text("LICENSE")

    assert license_text.startswith("MIT License")
    assert "Copyright (c) 2026 Arawn" in license_text
    assert "THE SOFTWARE IS PROVIDED \"AS IS\"" in license_text


def test_privacy_document_covers_policy_gated_agent_boundaries():
    privacy = read_text("docs/PRIVACY.md").lower()

    required = [
        "foreground policy-gated repair agent",
        "general shell grant",
        "grant ai root repair commands",
        "read-only diagnostics",
        "the policy gate does not authorize arbitrary model-authored code",
        "repairs are still consequential",
        "redaction is best effort",
        "share full terminal output",
        "continue without rollback",
        "/run/aurascan-agent/",
        "~/.local/state/aurascan/agent/",
        "/var/lib/aurascan/agent/",
        "hardware-related questions can trigger a foreground read-only hardware probe",
        "does not read or transmit system serial numbers",
    ]
    for phrase in required:
        assert phrase in privacy
    assert "foreground full-control repair agent" not in privacy
    assert "grant ai full root control" not in privacy
    assert "user-authorized remote code execution" not in privacy


def test_advisory_ai_documentation_keeps_model_prose_untrusted():
    readme = " ".join(read_text("README.md").lower().split())
    privacy = " ".join(read_text("docs/PRIVACY.md").lower().split())
    developing = " ".join(read_text("DEVELOPING.md").lower().split())
    checklist = " ".join(read_text("docs/RELEASE_CHECKLIST.md").lower().split())

    assert "model prose remains untrusted interpretation" in readme
    assert "sentence-leading imperative verbs" in readme
    assert "generic package-manager/install-helper advice" in readme
    assert "nominalized operation or invocation advice" in readme
    assert "not proof that arbitrary natural language is harmless" in readme
    assert "model prose remains untrusted interpretation" in privacy
    assert "sentence-leading imperative verbs" in privacy
    assert "generic package-manager/install-helper advice" in privacy
    assert "nominalized operation or invocation advice" in privacy
    assert "cannot prove arbitrary natural language harmless" in privacy
    assert "validated model prose is still untrusted interpretation" in developing
    assert "lexical guard cannot prove every natural-language construction inert" in developing
    assert "validated prose remains untrusted interpretation" in checklist
    assert "raw model prose is not persisted or rendered" not in readme
    assert "raw model responses are not persisted or rendered" not in privacy


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


def test_aur_maintainer_worm_v092_release_contract():
    def normalized(relative: str) -> str:
        return " ".join(read_text(relative).lower().split())

    readme = normalized("README.md")
    developing = normalized("DEVELOPING.md")
    agents = normalized("AGENTS.md")
    skill = normalized("SKILL.md")
    checklist = normalized("docs/RELEASE_CHECKLIST.md")
    release = normalized("docs/releases/v0.9.2.md")
    engine_source = read_text("aurascan/core/engine.py")

    propagation = get_rule_metadata("SUPPLYCHAIN-AUR-REPO-PROPAGATION-001")
    uninspected = get_rule_metadata("INSTALL-HOOK-UNINSPECTED-001")
    assert propagation is not None
    assert propagation.default_severity == Severity.CRITICAL
    assert uninspected is not None
    assert uninspected.default_severity == Severity.HIGH

    release_phrases = [
        "# aurascan v0.9.2",
        "released on 2026-08-30",
        "added `supplychain-aur-repo-propagation-001`, a critical hard blocker",
        "non-dry-run push bound to that aur endpoint or configured remote",
        "explicit pushes to another host",
        "arbitrary release tooling found only in acquired deep-static source",
        "added `install-hook-uninspected-001`, a high hard blocker",
        "bounded no-follow reads",
        "revalidates the complete input after scanning and again immediately before invoking",
        "does not prove package code ran",
        "package-scanner rule version advances from `1.2.0` to `1.3.0`",
        "instruction guard's report schema and rule version remain `1.0`",
        "application and arch/aur package advance to v0.9.2",
    ]
    for phrase in release_phrases:
        assert phrase in release
    readme_phrases = [
        "`supplychain-aur-repo-propagation-001` applies only to deterministic pkgbuild or declared install-hook control text",
        "non-dry-run push bound to the aur endpoint or configured remote",
        "declared relative path under the package directory is a symlink",
        "does not prove that the hook ran",
        "not apply the rule as a blanket check to every file acquired by `--deep-static`",
    ]
    for phrase in readme_phrases:
        assert phrase in readme

    developing_phrases = [
        "restrict it to pkgbuild text and declared install-hook text",
        "pushes explicitly bound to other hosts",
        "declared relative hook path under the package directory",
        "an unresolved hook must never reuse or store an allow decision",
    ]
    for phrase in developing_phrases:
        assert phrase in developing

    checklist_phrases = [
        "for v0.9.2, the package-scanner rule version is `1.3.0`",
        "`supplychain-aur-repo-propagation-001` remains a critical, non-reviewable blocker",
        "arbitrary release tooling found only in acquired deep-static source remains negative",
        "`install-hook-uninspected-001` remains a high, non-reviewable blocker",
        "every component of the declared relative hook path under the package directory",
        "an unresolved or changed hook cannot reuse or store an allow decision or review acceptance",
    ]
    for phrase in checklist_phrases:
        assert phrase in checklist

    shared_path_contract = "declared relative hook path under the package directory"
    assert shared_path_contract in agents
    assert shared_path_contract in skill


def test_hostile_content_v0100_release_contract():
    def normalized(relative: str) -> str:
        return " ".join(read_text(relative).lower().split())

    release = normalized("docs/releases/v0.10.0.md")
    checklist = normalized("docs/RELEASE_CHECKLIST.md")
    engine_source = read_text("aurascan/core/engine.py")

    required_release_phrases = [
        "# aurascan v0.10.0",
        "released on 2026-08-30",
        "hostile ai and repair boundaries",
        "ai cannot lower deterministic severity",
        "policy-gated repair agent replaces general shell behavior",
        "remote stages and opaque carriers",
        "unknown transformations that feed a later executed sink become high incomplete-inspection blockers",
        "images and other opaque bytes are never rendered or sent to a multimodal model",
        "source, archive, and tool hardening",
        "application and arch/aur package advance to v0.10.0",
        "rule version advances from `1.3.0` to `1.4.0`",
        "scanner version remains `2.5.0`",
        "instruction guard report schema and rule version remain `1.0`",
    ]
    for phrase in required_release_phrases:
        assert phrase in release

    assert "for v0.10.0, the package-scanner rule version is `1.4.0`" in checklist
    assert 'self.scanner_version = "2.5.0"' in engine_source


def test_instruction_review_v0101_release_contract():
    def normalized(relative: str) -> str:
        return " ".join(read_text(relative).lower().split())

    release = normalized("docs/releases/v0.10.1.md")
    checklist = normalized("docs/RELEASE_CHECKLIST.md")
    announcement = normalized("docs/ANNOUNCEMENT.md")
    engine_source = read_text("aurascan/core/engine.py")
    instruction_source = read_text("aurascan/core/instruction_guard.py")

    required_release_phrases = [
        "# aurascan v0.10.1",
        "released on 2026-08-31",
        "actionable instruction guard reviews",
        "suspicious instructions, incomplete scan or discovery coverage, and new or changed files awaiting integrity approval",
        "exact one-based contributing line ranges",
        "bounded ai explanations are mapped to deterministic evidence and labeled advisory",
        "`-a file_id` is the compact alias",
        "internal analysis evidence version advances to `1.2`",
        "package scanner remains scanner version `2.5.0` and rule version `1.4.0`",
        "application and arch/aur package advance to v0.10.1",
    ]
    for phrase in required_release_phrases:
        assert phrase in release

    assert "for v0.10.1, instruction guard terminal reviews keep suspicious content" in checklist
    assert "instruction guard report schema and rule version remain `1.0` for v0.10.1" in checklist
    assert "v0.10.1 release redesigns agent instruction guard reviews" in announcement
    assert 'self.scanner_version = "2.5.0"' in engine_source
    assert 'INSTRUCTION_GUARD_SCHEMA_VERSION = "1.0"' in instruction_source
    assert 'INSTRUCTION_GUARD_RULE_VERSION = "1.0"' in instruction_source
    assert 'INSTRUCTION_GUARD_EVIDENCE_VERSION = "1.1"' in instruction_source
    assert 'INSTRUCTION_GUARD_ANALYSIS_EVIDENCE_VERSION = "1.2"' in instruction_source


def test_repository_provenance_v0102_release_contract():
    def normalized(relative: str) -> str:
        return " ".join(read_text(relative).lower().split())

    release = normalized("docs/releases/v0.10.2.md")
    checklist = normalized("docs/RELEASE_CHECKLIST.md")
    announcement = normalized("docs/ANNOUNCEMENT.md")
    engine_source = read_text("aurascan/core/engine.py")
    scan_input_source = read_text("aurascan/core/install_hook.py")
    repository_source = read_text("aurascan/core/repository_provenance.py")
    instruction_source = read_text("aurascan/core/instruction_guard.py")

    required_release_phrases = [
        "# aurascan v0.10.2",
        "released on 2026-09-01",
        "aur repository artifact provenance",
        "always-on, bounded, no-follow snapshot",
        "`aur-repo-opaque-artifact-001` requests medium, non-hard-blocking",
        "`aur-repo-opaque-binary-001` requests high manual review",
        "`aur-repo-opaque-binary-exec-001` is critical and blocking",
        "declares its upstream https archive with a fixed checksum",
        "`aur-repo-inspection-incomplete-001` is a high, non-reviewable blocker",
        "does not invoke git and cannot prove that a file was committed",
        "package-scanner rule version advances from `1.4.0` to `1.5.0`",
        "scanner version remains `2.5.0`",
        "repository snapshot version starts at `1.0`",
        "package scan-input version advances to `2.0`",
        "instruction guard report schema and rule version remain `1.0`",
        "application and arch/aur package advance to v0.10.2",
    ]
    for phrase in required_release_phrases:
        assert phrase in release

    assert "for v0.10.2, the package-scanner rule version is `1.5.0`" in checklist
    assert "v0.10.2 release adds an always-on static provenance check" in announcement
    assert 'self.scanner_version = "2.5.0"' in engine_source
    assert 'self.rule_version = "1.5.0"' in engine_source
    assert 'PACKAGE_SCAN_INPUT_VERSION = "2.0"' in scan_input_source
    assert 'REPOSITORY_SNAPSHOT_VERSION = "1.0"' in repository_source
    assert 'INSTRUCTION_GUARD_SCHEMA_VERSION = "1.0"' in instruction_source
    assert 'INSTRUCTION_GUARD_RULE_VERSION = "1.0"' in instruction_source
    assert get_rule_metadata("AUR-REPO-OPAQUE-ARTIFACT-001").default_severity == Severity.MEDIUM
    assert get_rule_metadata("AUR-REPO-OPAQUE-BINARY-001").default_severity == Severity.HIGH
    assert get_rule_metadata("AUR-REPO-OPAQUE-BINARY-EXEC-001").default_severity == Severity.CRITICAL
    assert get_rule_metadata("AUR-REPO-INSPECTION-INCOMPLETE-001").default_severity == Severity.HIGH


def test_recovery_bearing_v0103_release_contract():
    import json

    def normalized(relative: str) -> str:
        return " ".join(read_text(relative).lower().split())

    release_text = read_text("docs/releases/v0.10.3.md")
    release = " ".join(release_text.lower().split())
    unreleased = normalized("docs/releases/unreleased.md")
    checklist = normalized("docs/RELEASE_CHECKLIST.md")
    announcement = normalized("docs/ANNOUNCEMENT.md")
    pkgbuild = read_text("packaging/arch/PKGBUILD")
    srcinfo = read_text("packaging/arch/.SRCINFO")
    recovery_source = read_text("aurascan/core/recovery_cli.py")
    profile = read_text("packaging/recovery/archiso/profiledef.sh")
    archiso_issue = read_text("packaging/recovery/archiso/airootfs/etc/issue")
    uki_issue = read_text("packaging/recovery/rootfs/etc/issue")
    manifest = json.loads(read_text("aurascan/assets/aurascan-recovery-iso.json"))

    required_release_phrases = [
        "# aurascan v0.10.3",
        "released on 2026-09-01",
        "recovery-bearing release",
        "first time since v0.6.0",
        "`aurascan-recovery-0.10.3-x86_64.iso`",
        "sorted `.iso.packages.txt` manifest",
        "rejects a github release asset at or above 2 gib",
        "fresh work and output locations",
        "either `recovery-bearing` or `package-only`",
        "locally built ukis remain specific",
        "package-scanner rule version remains `1.5.0`",
        "previous release or tag is rewritten",
        "application and arch/aur package advance to v0.10.3",
    ]
    for phrase in required_release_phrases:
        assert phrase in release

    assert "changes after v0.10.3 will be recorded here" in unreleased
    assert "release disposition" in checklist
    assert "strictly smaller than 2 gib (2,147,483,648 bytes)" in checklist
    assert "v0.10.3 release refreshes the optional hybrid bios/uefi" in announcement
    assert "pkgver=0.10.3" in pkgbuild
    assert "pkgrel=1" in pkgbuild
    assert "sha256sums=('SKIP')" in pkgbuild or re.search(r"sha256sums=\('[0-9a-f]{64}'\)", pkgbuild)
    assert "\tpkgver = 0.10.3" in srcinfo
    assert "aurascan-0.10.3.tar.gz" in srcinfo
    assert "\tsha256sums = SKIP" in srcinfo or re.search(r"\tsha256sums = [0-9a-f]{64}", srcinfo)
    assert 'return "0.10.3-dev"' in recovery_source
    assert ': "${AURASCAN_RECOVERY_VERSION:' in profile
    assert 'iso_version="$AURASCAN_RECOVERY_VERSION"' in profile
    assert "AuraScan Recovery v@AURASCAN_VERSION@" in archiso_issue
    assert "AuraScan Recovery" in uki_issue
    assert "v0.6.0" not in uki_issue
    assert manifest["schema"] == "aurascan_recovery_iso/2.0"
    assert manifest["application_version"] == "0.10.3"
    assert manifest["release_disposition"] == "recovery-bearing"
    assert manifest["version"] == "0.10.3"
    assert manifest["architecture"] == "x86_64"
    assert manifest["filename"] == "aurascan-recovery-0.10.3-x86_64.iso"
    assert manifest["released_at"] == "2026-09-01"
    assert manifest["status"] in {"build-required", "release-ready"}
    if manifest["status"] == "build-required":
        assert manifest["url"] == ""
        assert manifest["sha256"] == ""
    else:
        assert manifest["url"].endswith(
            "/v0.10.3/aurascan-recovery-0.10.3-x86_64.iso"
        )
        assert re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])

    if os.environ.get("AURASCAN_RELEASE_FINAL") == "1":
        assert os.environ.get("AURASCAN_RELEASE_TAG") == "v0.10.3"
        assert manifest["status"] == "release-ready"
        assert re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])
        forbidden_release_phrases = (
            "pending-validation",
            "will be pinned",
            "will name",
            "final release record will",
            "required recovery-bearing gates include",
            "remaining required gates",
        )
        for phrase in forbidden_release_phrases:
            assert phrase not in release
        rc_commits = re.findall(
            r"^Recovery build candidate: `([0-9a-f]{40})`$",
            release_text,
            re.MULTILINE,
        )
        assert len(rc_commits) == 1
        release_digests = re.findall(
            r"^ISO SHA-256: `([0-9a-f]{64})`$",
            release_text,
            re.MULTILINE,
        )
        assert release_digests == [manifest["sha256"]]
        required_boot_outcomes = (
            "- hybrid iso, seabios readiness: `pass`",
            "- hybrid iso, ovmf uefi readiness: `pass`",
            "- local uki, ordinary ovmf uefi readiness: `pass`",
            "- local uki, disposable-key secure boot unsigned rejection and signed readiness: `pass`",
        )
        for outcome in required_boot_outcomes:
            assert outcome in release
        required_additional_outcomes = (
            "- complete python suite and python 3.8/3.14 ci matrix: `pass`",
            "- presenter, shell-syntax, unit, and package-metadata audits: `pass`",
            "- clean arch release-candidate package build: `pass`",
            "- expanded-artifact privacy/path audit: `pass`",
            "- strict sub-2-gib iso size gate: `pass`",
            "- deterministic recovery scenario fixtures: `pass`",
        )
        for outcome in required_additional_outcomes:
            assert outcome in release
        assert "sha256sums=('skip')" in pkgbuild.lower()


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
        "Policy-Gated Repair Agent defaults to `guarded`",
        "Root-shell also requires a safe root-owned policy",
        "GRANT AI ROOT REPAIR COMMANDS",
        "fail-closed command",
        "rather than Full",
        "Hardware-aware follow-up runs only in an opted-in foreground AI workflow",
        "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001",
        "INSTALL-HOOK-UNINSPECTED-001",
        "For v0.10.0, the package-scanner rule version is `1.4.0`",
        "For v0.10.1, Instruction Guard terminal reviews keep suspicious content",
        "For v0.10.2, the package-scanner rule version is `1.5.0`",
        "AUR-REPO-OPAQUE-BINARY-EXEC-001",
        "AUR-REPO-INSPECTION-INCOMPLETE-001",
        "Release Disposition",
        "recovery-bearing",
        "package-only",
        "strictly smaller than 2 GiB",
        "Any unrun or failed gate is reported exactly",
    ]
    for phrase in required_phrases:
        assert phrase in checklist
    assert "user-authorized remote code execution" not in checklist


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
