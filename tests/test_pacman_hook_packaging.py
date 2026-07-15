from io import StringIO
import os
from pathlib import Path
import re
import tomllib

from aurascan.cli import (
    build_parser,
    read_pacman_hook_targets,
    resolve_pacman_hook_target,
    scan_pacman_hook_targets,
)


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def hook_fields(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields.setdefault(key.strip(), []).append(value.strip())
    return fields


def assert_release_hook_is_safe(text: str) -> None:
    fields = hook_fields(text)
    assert "/home/arawn" not in text
    assert ".venv" not in text
    assert "PYTHONPATH=" not in text
    assert "python3 -m" not in text
    assert fields["Operation"] == ["Install", "Upgrade"]
    assert fields["Type"] == ["Package"]
    assert fields["Target"] == ["*"]
    assert fields["When"] == ["PreTransaction"]
    assert fields["Exec"] == ["/usr/bin/aurascan"]
    assert "NeedsTargets" in text
    assert "--scan-context" not in text
    assert "--update-scan-policy" not in text
    assert "--deep-static" not in text


def test_root_release_hook_is_release_safe():
    assert_release_hook_is_safe(read_text("aurascan.hook"))


def test_packaging_release_hook_is_release_safe():
    assert_release_hook_is_safe(read_text("packaging/arch/aurascan.hook"))


def test_dev_hook_is_clearly_marked_development_only():
    text = read_text("contrib/dev/aurascan-dev.hook.example")

    assert "Development-only" in text
    assert "Do not install this file on a normal system" in text
    assert "/home/arawn" not in text
    assert ".venv" not in text
    assert "/path/to/AuraScan" in text


def test_packaging_readme_documents_hook_limitations_and_recovery():
    text = read_text("packaging/arch/README.md").lower()

    required = [
        "pip install does not install pacman hooks",
        "/usr/share/libalpm/hooks/aurascan.hook",
        "does not protect against malicious pkgbuild build-time logic",
        "use `aurascan-makepkg`",
        "does not pass `--scan-context update`",
        "does not enable `--update-scan-policy smart`",
        "missing package archive targets are reported as warnings",
        "if `/usr/bin/aurascan` is missing",
        "aurascan.install",
        "advisory text only",
        "must not prompt",
    ]
    for phrase in required:
        assert phrase in text


def test_arch_pkgbuild_references_advisory_install_script():
    text = read_text("packaging/arch/PKGBUILD")

    assert "install=aurascan.install" in text


def test_arch_package_metadata_targets_current_public_release():
    pyproject = tomllib.loads(read_text("pyproject.toml"))
    version = pyproject["project"]["version"]
    pkgbuild = read_text("packaging/arch/PKGBUILD")
    srcinfo = read_text("packaging/arch/.SRCINFO")
    release_notes = ROOT / "docs" / "releases" / f"v{version}.md"
    is_git_checkout = (ROOT / ".git").exists()

    assert re.search(rf"^pkgver={re.escape(version)}$", pkgbuild, re.MULTILINE)
    assert f"v$pkgver.tar.gz" in pkgbuild
    # A tagged archive cannot contain the checksum of itself. The checkout
    # metadata is finalized and validated immediately after the tag exists.
    if is_git_checkout:
        assert 'sha256sums=(\'SKIP\')' not in pkgbuild
    assert 'cd "AuraScan-$pkgver"' in pkgbuild
    assert 'cd "$pkgname-$pkgver"' not in pkgbuild
    assert 'python -m installer --destdir="$pkgdir" --prefix=/usr dist/*.whl' in pkgbuild
    assert "Arch-family package, AUR, and upgrade workflows" in pkgbuild
    assert "shelly: optional Shelly update handoff for aurascan upgrade" in pkgbuild
    assert f"pkgver = {version}" in srcinfo
    assert "pkgdesc = AI-assisted safety layer for Arch-family package, AUR, and upgrade workflows" in srcinfo
    assert "optdepends = shelly: optional Shelly update handoff for aurascan upgrade" in srcinfo
    assert f"aurascan-{version}.tar.gz::https://github.com/crizzler/AuraScan/archive/refs/tags/v{version}.tar.gz" in srcinfo
    if is_git_checkout:
        assert "sha256sums = SKIP" not in srcinfo
    assert release_notes.exists()


def test_arch_pkgbuild_installs_updater_assets():
    text = read_text("packaging/arch/PKGBUILD")
    srcinfo = read_text("packaging/arch/.SRCINFO")

    assert "python-pyqt6: AuraScan Updater tray applet" in text
    assert "aurascan/assets/aurascan-updater.desktop" in text
    assert "aurascan/assets/aurascan-updater.svg" in text
    assert "/usr/share/applications/aurascan-updater.desktop" in text
    assert "/usr/share/icons/hicolor/scalable/apps/aurascan-updater.svg" in text
    assert "aurascan-updater-maintenance.svg" in text
    assert "aurascan-updater-attention.svg" in text
    assert "aurascan-updater-critical.svg" in text
    assert 'docs/PRIVACY.md "$pkgdir/usr/share/doc/$pkgname/PRIVACY.md"' in text
    assert "python-pyqt6: AuraScan Updater tray applet" in srcinfo


def test_arch_pkgbuild_installs_disabled_hardened_incident_monitor():
    pkgbuild = read_text("packaging/arch/PKGBUILD")
    srcinfo = read_text("packaging/arch/.SRCINFO")
    service = read_text("aurascan/assets/aurascan-incident-monitor.service")
    tmpfiles = read_text("aurascan/assets/aurascan-incidents.conf")
    maintenance_service = read_text("aurascan/assets/aurascan-incident-maintenance.service")
    maintenance_timer = read_text("aurascan/assets/aurascan-incident-maintenance.timer")
    assistant_service = read_text("aurascan/assets/aurascan-incident-assistant.service")
    assistant_timer = read_text("aurascan/assets/aurascan-incident-assistant.timer")
    safe_service = read_text("aurascan/assets/aurascan-incident-safe-autopilot.service")

    assert "aurascan/assets/aurascan-incident-monitor.service" in pkgbuild
    assert "/usr/lib/systemd/system/aurascan-incident-monitor.service" in pkgbuild
    assert "/usr/lib/systemd/system/aurascan-incident-maintenance.service" in pkgbuild
    assert "/usr/lib/systemd/system/aurascan-incident-maintenance.timer" in pkgbuild
    assert "/usr/lib/systemd/system/aurascan-incident-safe-autopilot.service" in pkgbuild
    assert "/usr/lib/systemd/user/aurascan-incident-assistant.service" in pkgbuild
    assert "/usr/lib/systemd/user/aurascan-incident-assistant.timer" in pkgbuild
    assert "aurascan/assets/aurascan-incidents.conf" in pkgbuild
    assert "/usr/lib/tmpfiles.d/aurascan-incidents.conf" in pkgbuild
    assert "pacman-contrib: bounded package-cache cleanup for incident recovery" in pkgbuild
    assert "pacman-contrib: bounded package-cache cleanup for incident recovery" in srcinfo
    assert "ExecStart=/usr/bin/aurascan incidents --last-boot --capture-monitor" in service
    assert "PrivateNetwork=yes" in service
    assert "UnsetEnvironment=AURASCAN_AI_KEY" in service
    assert "NoNewPrivileges=yes" in service
    assert "ProtectSystem=strict" in service
    assert "StateDirectory=aurascan/incidents" in service
    assert "ReadWritePaths=/var/lib/aurascan/incidents" in service
    assert "ExecStart=/usr/bin/aurascan incidents --current-boot --capture-maintenance" in maintenance_service
    assert "PrivateNetwork=yes" in maintenance_service
    assert "UnsetEnvironment=AURASCAN_AI_KEY" in maintenance_service
    assert "CPUWeight=10" in maintenance_service
    assert "IOWeight=10" in maintenance_service
    assert "OnCalendar=weekly" in maintenance_timer
    assert "Persistent=true" in maintenance_timer
    assert "RandomizedDelaySec=2h" in maintenance_timer
    assert "OnSuccess=aurascan-incident-safe-autopilot.service" in service
    assert "OnSuccess=aurascan-incident-safe-autopilot.service" in maintenance_service
    assert "ExecStart=/usr/bin/aurascan incidents --background-assist" in assistant_service
    assert "PrivateNetwork=yes" not in assistant_service
    assert "NoNewPrivileges=yes" in assistant_service
    assert "CapabilityBoundingSet=" in assistant_service
    assert "TimeoutStartSec=300" in assistant_service
    assert "OnUnitActiveSec=5m" in assistant_timer
    assert "ExecCondition=/usr/bin/aurascan incidents --safe-autopilot-enabled" in safe_service
    assert "ExecStart=/usr/bin/aurascan incidents --capture-safe-autopilot" in safe_service
    assert "PrivateNetwork=yes" in safe_service
    assert "UnsetEnvironment=AURASCAN_AI_KEY" in safe_service
    assert "IPAddressDeny=any" in safe_service
    assert "ProtectProc=ptraceable" in safe_service
    assert "ReadWritePaths=/var/lib/aurascan/incidents /var/lib/pacman /etc/pacman.d" in safe_service
    assert "/var/lib/aurascan/incidents/pending" in tmpfiles
    assert "/var/lib/aurascan/incidents/automation" in tmpfiles
    assert "systemctl enable" not in pkgbuild
    assert "systemctl start" not in pkgbuild
    assert "systemctl enable" not in maintenance_timer
    assert "WantedBy=" not in safe_service


def test_updater_desktop_asset_is_release_safe():
    text = read_text("aurascan/assets/aurascan-updater.desktop")

    assert "Name=AuraScan Updater" in text
    assert "Exec=aurascan updater" in text
    assert "Icon=aurascan-updater" in text
    assert "/home/" not in text
    assert ".venv" not in text


def test_arch_install_script_is_advisory_only():
    text = read_text("packaging/arch/aurascan.install")
    stripped_command_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in {"post_install() {", "post_upgrade() {", "cat <<'EOF'", "EOF", "}"}:
            continue
        if stripped.startswith("AuraScan ") or stripped.startswith("Run ") or stripped.startswith("Check ") or stripped.startswith("For ") or stripped.startswith("Review "):
            continue
        if stripped.startswith("aurascan "):
            continue
        if stripped == "aurascan-makepkg":
            continue
        stripped_command_lines.append(stripped)

    assert "post_install() {" in text
    assert "post_upgrade() {" in text
    assert "aurascan init" in text
    assert "aurascan doctor" in text
    assert "aurascan-makepkg" in text
    assert stripped_command_lines == []
    assert "read " not in text
    assert "sudo" not in text
    assert "pacman" not in text
    assert "makepkg " not in text
    assert "curl" not in text
    assert "wget" not in text
    assert "AURASCAN_" not in text


def test_readme_documents_hook_install_uninstall_and_wrapper_boundary():
    text = read_text("README.md").lower()
    normalized = " ".join(text.split())

    required = [
        "pip install does not install pacman hooks",
        "/usr/share/libalpm/hooks/aurascan.hook",
        "/etc/pacman.d/hooks/",
        "do not leave a hook behind that points to a missing executable",
        "the pacman hook scans built package archives",
        "aurascan-makepkg` scans before makepkg executes package build functions",
        "does not provide a verified pacman transaction context provider",
    ]
    for phrase in required:
        assert phrase in normalized


def test_release_checklist_mentions_hook_release_gates():
    text = read_text("docs/RELEASE_CHECKLIST.md")

    required = [
        "Release pacman hook template has no developer-local paths.",
        "Release pacman hook install path is checked.",
        "Pacman hook uninstall path is documented.",
        "Pacman hook failure recovery is documented.",
        "`aurascan-makepkg` is documented as build-time protection.",
        "Pacman hook is documented as archive/install-stage protection.",
        "Root-level development hooks are not accidentally packaged.",
    ]
    for phrase in required:
        assert phrase in text


def test_cli_help_mentions_pacman_hook_mode_boundary():
    help_text = build_parser().format_help()
    normalized = " ".join(help_text.split())

    assert "Pacman hook mode" in help_text
    assert "NeedsTargets" in help_text
    assert "aurascan updater" in help_text
    assert "aurascan incidents" in help_text
    assert "not a replacement for aurascan-makepkg" in normalized


def test_hook_stdin_target_parser_preserves_target_lines():
    stream = StringIO("demo\n/tmp/example.pkg.tar.zst\n")

    assert read_pacman_hook_targets(stream) == ["demo", "/tmp/example.pkg.tar.zst"]


def test_hook_target_resolution_uses_existing_path(tmp_path):
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    package.write_bytes(b"fixture")

    assert resolve_pacman_hook_target(str(package), cache_dir=tmp_path) == str(package)


def test_hook_target_resolution_uses_latest_cache_match(tmp_path):
    old = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    new = tmp_path / "demo-1.1-1-x86_64.pkg.tar.zst"
    old.write_bytes(b"old")
    new.write_bytes(b"new")
    os.utime(old, (1, 1))
    os.utime(new, (2, 2))

    assert resolve_pacman_hook_target("demo", cache_dir=tmp_path) == str(new)


class FakeHookEngine:
    def __init__(self, results):
        self.results = list(results)
        self.scanned = []

    def scan_package(self, path):
        self.scanned.append(path)
        return self.results.pop(0)


def test_hook_scan_missing_target_warns_but_does_not_fail(tmp_path):
    engine = FakeHookEngine([])
    stderr = StringIO()

    ok = scan_pacman_hook_targets(engine, ["missing"], cache_dir=tmp_path, stderr=stderr)

    assert ok is True
    assert engine.scanned == []
    assert "Could not locate package file for missing" in stderr.getvalue()


def test_hook_scan_blocking_result_returns_failure(tmp_path):
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    package.write_bytes(b"fixture")
    engine = FakeHookEngine([False])

    ok = scan_pacman_hook_targets(engine, [str(package)], cache_dir=tmp_path, stderr=StringIO())

    assert ok is False
    assert engine.scanned == [str(package)]
