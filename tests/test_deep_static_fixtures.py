import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.core.archive import SafeArchiveExtractor
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
from aurascan.core.models import AnalysisResult
from aurascan.core.source_acquisition import (
    PgpKeyNormalizer,
    PublicKeySource,
    SignatureVerifier,
    SourceFetcher,
    SourcePolicy,
)
from tests.helpers.archive_fixtures import (
    sha256_file,
    write_deep_static_archive,
    write_public_key_fixture,
    write_signature_fixture,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "curated_packages" / "deep_static"
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

SIGNER_FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
MISMATCH_FINGERPRINT = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"


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


class FixtureKeyProvider:
    def __init__(self, key_path=None, error="KEY_UNAVAILABLE"):
        self.key_path = key_path
        self.error = error
        self.requests = []

    def get_key(self, fingerprint):
        normalized = PgpKeyNormalizer.normalize(fingerprint)
        self.requests.append(normalized)
        if self.key_path is not None:
            return PublicKeySource(normalized, self.key_path, "test_fixture")
        return PublicKeySource(normalized, error=self.error)


class FakeGpgRunner:
    def __init__(self, signer_fingerprint=SIGNER_FINGERPRINT, verify_returncode=0):
        self.signer_fingerprint = signer_fingerprint
        self.verify_returncode = verify_returncode
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if "--import" in args:
            return subprocess.CompletedProcess(args, 0, "[GNUPG:] IMPORT_OK 1 fixture\n", "")
        if self.verify_returncode != 0:
            return subprocess.CompletedProcess(args, self.verify_returncode, "[GNUPG:] BADSIG BAD fixture\n", "")
        status = (
            f"[GNUPG:] VALIDSIG {self.signer_fingerprint} 2026-01-01 "
            f"0 4 0 1 10 00 {self.signer_fingerprint}\n"
        )
        return subprocess.CompletedProcess(args, 0, status, "")


@dataclass
class PreparedFixture:
    pkgbuild: Path
    archive: Path
    key_provider: FixtureKeyProvider
    gpg_runner: FakeGpgRunner
    source_fetcher: SourceFetcher


def manifests():
    items = []
    for path in sorted(FIXTURE_ROOT.iterdir()):
        manifest_path = path / "expected.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["path"] = path
            items.append(manifest)
    return items


def manifest_ids():
    return [manifest["scenario"] for manifest in manifests()]


@pytest.mark.parametrize("manifest", manifests(), ids=manifest_ids())
def test_deep_static_curated_fixtures(manifest, tmp_path, monkeypatch, capsys):
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    if manifest.get("pgp_fixture"):
        monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    prepared = prepare_fixture(manifest, tmp_path)
    engine = engine_for(tmp_path, manifest, prepared.source_fetcher)

    engine.scan_pkgbuild(
        str(prepared.pkgbuild),
        pkg_name=manifest["package_name"],
        pkg_ver=manifest["package_version"],
    )

    output = strip_ansi(capsys.readouterr().out)
    report = engine.last_report
    assert_report_expectations(report, manifest)
    assert_deep_static_safety(report, manifest, prepared, fake_home)

    for snippet in manifest.get("expected_terminal_contains", []):
        assert snippet in output


def test_deep_static_fixture_manifests_cover_required_categories():
    all_manifests = manifests()
    categories = {manifest["category"] for manifest in all_manifests}
    covered_rules = {rule for manifest in all_manifests for rule in manifest.get("expected_rule_ids", [])}

    assert {"deep_static_archive", "deep_static_pgp", "deep_static_source_content"} <= categories
    assert {
        "ARCHIVE-PATH-TRAVERSAL",
        "ARCHIVE-SYMLINK-ESCAPE",
        "ARCHIVE-HARDLINK-ESCAPE",
        "ARCHIVE-TOO-MANY-FILES",
        "ARCHIVE-OVERSIZED",
        "ARCHIVE-NESTED-DEPTH",
        "SIGNATURE-VERIFIED",
        "SIGNATURE-INVALID",
        "SIGNATURE-FINGERPRINT-MISMATCH",
        "KEY_UNAVAILABLE",
        "SOURCE-VALIDPGPKEY-WEAK",
        "DEEPSTATIC-SETUPPY-SUSPICIOUS",
        "DEEPSTATIC-NPM-INSTALL-SCRIPT",
        "DEEPSTATIC-TOKEN-REFERENCE",
        "DEEPSTATIC-VENDORED-DEPS",
        "DEEPSTATIC-MINIFIED-FILE",
    } <= covered_rules


def test_deep_static_fixtures_are_text_templates_not_generated_archives():
    for path in FIXTURE_ROOT.rglob("*"):
        if not path.is_file():
            continue
        assert path.suffix in {".json", ".md", ""} or path.name == "PKGBUILD"


def prepare_fixture(manifest, tmp_path) -> PreparedFixture:
    work = tmp_path / manifest["scenario"]
    shutil.copytree(manifest["path"], work)

    archive = write_deep_static_archive(work / "src.tar", manifest["archive_scenario"])
    signature = None
    key_path = None
    pgp_fixture = manifest.get("pgp_fixture")
    if pgp_fixture:
        signature = write_signature_fixture(work / "src.tar.sig", f"{pgp_fixture} signature fixture\n")
        if pgp_fixture not in {"key_unavailable", "weak_validpgpkeys"}:
            key_path = write_public_key_fixture(work / "fixture-key.asc", SIGNER_FINGERPRINT)

    replacements = {
        "__SHA256__": sha256_file(archive),
        "__VALID_FINGERPRINT__": SIGNER_FINGERPRINT,
        "__MISMATCH_FINGERPRINT__": MISMATCH_FINGERPRINT,
    }
    pkgbuild = work / "PKGBUILD"
    text = pkgbuild.read_text(encoding="utf-8")
    for marker, value in replacements.items():
        text = text.replace(marker, value)
    pkgbuild.write_text(text, encoding="utf-8")

    key_provider = FixtureKeyProvider(key_path)
    if pgp_fixture == "key_unavailable":
        key_provider = FixtureKeyProvider(None)
    runner = runner_for(pgp_fixture)
    policy = SourcePolicy(
        offline=True,
        auto_key_fetch=False,
        trusted_key_dirs=[],
        key_cache_dir=tmp_path / "key-cache",
    )
    verifier = SignatureVerifier(policy=policy, key_provider=key_provider, runner=runner)
    fetcher = SourceFetcher(policy=policy, signature_verifier=verifier)

    assert archive.exists()
    if pgp_fixture:
        assert signature and signature.exists()
    return PreparedFixture(pkgbuild, archive, key_provider, runner, fetcher)


def runner_for(pgp_fixture):
    if pgp_fixture == "invalid":
        return FakeGpgRunner(verify_returncode=1)
    return FakeGpgRunner(signer_fingerprint=SIGNER_FINGERPRINT)


def engine_for(tmp_path, manifest, source_fetcher):
    engine = AuraScanEngine(deep_static=False, offline=True, auto_key_fetch=False)
    engine.deep_static = True
    engine.cache = ScanCache(tmp_path / f"cache-{manifest['scenario']}")
    engine.analyzers = [
        DeepStaticAnalyzer(
            extractor=extractor_for(manifest),
            clamav=FakeClamAV(),
            source_fetcher=source_fetcher,
        )
    ]
    return engine


def extractor_for(manifest):
    limits = dict(manifest.get("extractor_limits", {}))
    return SafeArchiveExtractor(**limits)


def assert_report_expectations(report, manifest):
    expected = set(manifest.get("expected_rule_ids", []))
    absent = set(manifest.get("expected_absent_rule_ids", []))
    actual = rule_ids(report)
    assert expected <= actual
    assert absent.isdisjoint(actual)

    expected_phases = set(manifest.get("expected_phases", []))
    assert expected_phases <= phases(report)

    risk = report.get("risk_summary") or {}
    min_severity = manifest.get("expected_min_severity")
    if min_severity:
        assert SEVERITY_ORDER[risk["severity"]] >= SEVERITY_ORDER[min_severity]
    if manifest.get("expected_not_critical"):
        assert risk["severity"] != "CRITICAL"
    if manifest.get("expected_action"):
        assert risk["recommended_action"] == manifest["expected_action"]
    if "expected_manual_review" in manifest:
        assert risk["requires_manual_review"] is manifest["expected_manual_review"]
    if "expected_hard_blocker" in manifest:
        assert risk["blocks_installation"] is manifest["expected_hard_blocker"]


def assert_deep_static_safety(report, manifest, prepared, fake_home):
    assert manifest.get("expected_deep_static_required") is True
    assert report["source_acquisition"]
    assert all(item["kind"] in {"local", "signature"} for item in report["source_acquisition"])

    if manifest.get("expected_no_network"):
        assert all("://" not in item["resolved"] for item in report["source_acquisition"])

    if manifest.get("expected_no_user_keyring"):
        assert not prepared.key_provider.requests or all(
            request in {SIGNER_FINGERPRINT, MISMATCH_FINGERPRINT}
            for request in prepared.key_provider.requests
        )
        for _args, kwargs in prepared.gpg_runner.calls:
            env = kwargs["env"]
            assert env["GNUPGHOME"] != os.environ.get("GNUPGHOME")
            assert env["HOME"] != str(Path.home())
            assert not Path(env["GNUPGHOME"]).is_relative_to(fake_home)

    if manifest["scenario"] == "archive_path_traversal":
        assert not (prepared.pkgbuild.parent.parent / "evil.txt").exists()

    if manifest["scenario"] == "pgp_valid_signature":
        verified = [
            finding for finding in report["findings"]
            if finding["rule_id"] == "SIGNATURE-VERIFIED"
        ]
        assert verified
        assert "not proof the source is safe" in verified[0]["recommendation"]


def rule_ids(report):
    return {finding["rule_id"] for finding in report.get("findings", [])}


def phases(report):
    return {finding["phase"] for finding in report.get("findings", [])}


def strip_ansi(text):
    return ANSI_RE.sub("", text)
