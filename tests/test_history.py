import json
from pathlib import Path

import pytest

from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.core.models import Severity
from aurascan.core.repository_provenance import (
    REPOSITORY_COMPLETE,
    RepositorySnapshot,
)


BASE_PKGBUILD = """# Maintainer: Alice <alice@example.invalid>
pkgname=demo
pkgver=1.0
source=("https://example.invalid/demo-1.0.tar.gz")
sha256sums=("abc")
validpgpkeys=("ABCDEF")
depends=("glibc")
prepare() {
  echo harmless
}
build() {
  echo harmless
}
"""


def test_first_scan_creates_baseline_without_findings(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)

    result = analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_PKGBUILD)

    assert result.findings == []
    assert analyzer.get_snapshot("demo") == {}
    analyzer.commit_pending_snapshots(scan_level="fast_default", scanner_version="test", rule_version="test")
    assert analyzer.get_snapshot("demo")["package_name"] == "demo"
    assert analyzer.get_snapshot("demo")["scan_status"] == "accepted"


def test_history_snapshot_persists_repository_identity_and_status(tmp_path: Path):
    analyzer = HistoryAnalyzer(tmp_path / "history.db")
    repository = RepositorySnapshot(
        status=REPOSITORY_COMPLETE,
        input_digest="a" * 64,
        artifacts=(),
    )

    analyzer.analyze_pkgbuild(
        str(tmp_path / "PKGBUILD"),
        BASE_PKGBUILD,
        repository_snapshot=repository,
    )
    analyzer.commit_pending_snapshots(scan_level="fast_default")

    saved = analyzer.get_snapshot("demo")
    assert saved["repository_input_digest"] == "a" * 64
    assert saved["repository_status"] == REPOSITORY_COMPLETE


def test_maintainer_annotation_source_and_pgp_change_emit_manual_review_findings(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)
    analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_PKGBUILD)
    analyzer.commit_pending_snapshots(scan_level="fast_default")

    changed = """# Maintainer: Bob <bob@example.invalid>
pkgname=demo
pkgver=1.1
source=("https://raw.githubusercontent.com/random/fork/demo.tar.gz")
sha256sums=("SKIP")
depends=("glibc" "curl")
build() {
  curl https://example.invalid/file -o file
}
"""

    result = analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), changed)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "HIST-MAINTAINER-ANNOTATION-CHANGED" in rule_ids
    assert not {"HIST-MAINTAINER-CHANGED", "HIST-ORPHAN-ADOPTED"} & rule_ids
    assert "HIST-SOURCE-HOST-CHANGED" in rule_ids
    assert "HIST-PGP-REMOVED" in rule_ids
    assert "HIST-BUILD-NEW-NETWORK" in rule_ids
    assert all(f.requires_manual_review for f in result.findings)
    assert not any(f.blocks_installation for f in result.findings)


@pytest.mark.parametrize(
    ("previous_annotation", "current_annotation"),
    [
        ("", "# Maintainer: Alice <alice@example.invalid>\n"),
        ("# Maintainer:\n", "# Maintainer: Alice <alice@example.invalid>\n"),
        ("# Maintainer: Alice <alice@example.invalid>\n", ""),
        ("# Maintainer: Alice <alice@example.invalid>\n", "# Maintainer:\n"),
        ("# Maintainer: Alice <alice@example.invalid>\n", "# Maintainer: Bob <bob@example.invalid>\n"),
    ],
)
def test_annotation_addition_removal_and_change_do_not_establish_aur_ownership(
    tmp_path: Path, previous_annotation, current_annotation
):
    analyzer = HistoryAnalyzer(tmp_path / "history.db")
    body = BASE_PKGBUILD.split("\n", 1)[1]
    path = str(tmp_path / "PKGBUILD")
    analyzer.analyze_pkgbuild(path, previous_annotation + body)
    analyzer.commit_pending_snapshots(scan_level="fast_default")

    result = analyzer.analyze_pkgbuild(path, current_annotation + body)

    assert [finding.rule_id for finding in result.findings] == ["HIST-MAINTAINER-ANNOTATION-CHANGED"]
    finding = result.findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.requires_manual_review is True
    assert finding.blocks_installation is False
    assert "Alice" not in json.dumps(finding.to_dict())
    assert "Bob" not in json.dumps(finding.to_dict())


@pytest.mark.parametrize(
    ("previous_annotation", "current_annotation"),
    [
        ("", ""),
        ("", "# Maintainer:  \n"),
        ("# Maintainer:\n", ""),
        ("# Maintainer: Alice\n", "  # Maintainer:  Alice  \n"),
    ],
)
def test_absent_blank_or_unchanged_annotation_does_not_report_adoption(
    tmp_path: Path, previous_annotation, current_annotation
):
    analyzer = HistoryAnalyzer(tmp_path / "history.db")
    body = BASE_PKGBUILD.split("\n", 1)[1]
    path = str(tmp_path / "PKGBUILD")
    analyzer.analyze_pkgbuild(path, previous_annotation + body)
    analyzer.commit_pending_snapshots(scan_level="fast_default")

    result = analyzer.analyze_pkgbuild(path, current_annotation + body)

    assert result.findings == []


def test_legacy_snapshot_without_maintainer_annotation_is_not_orphan_evidence(tmp_path: Path):
    analyzer = HistoryAnalyzer(tmp_path / "history.db")
    path = str(tmp_path / "PKGBUILD")
    analyzer.analyze_pkgbuild(path, BASE_PKGBUILD)
    analyzer.commit_pending_snapshots(scan_level="fast_default")
    legacy = analyzer.get_snapshot("demo")
    legacy.pop("maintainer")
    analyzer.save_snapshot("demo", legacy)

    result = analyzer.analyze_pkgbuild(path, BASE_PKGBUILD)

    assert [finding.rule_id for finding in result.findings] == ["HIST-MAINTAINER-ANNOTATION-CHANGED"]
    assert result.findings[0].requires_manual_review is True


def test_hostile_annotation_is_not_copied_into_history_finding(tmp_path: Path):
    analyzer = HistoryAnalyzer(tmp_path / "history.db")
    path = str(tmp_path / "PKGBUILD")
    analyzer.analyze_pkgbuild(path, BASE_PKGBUILD)
    analyzer.commit_pending_snapshots(scan_level="fast_default")
    hostile = "fake-secret-value \x1b[31m https://example.invalid/?token=fake-secret-value"
    changed = BASE_PKGBUILD.replace("Alice <alice@example.invalid>", hostile)

    result = analyzer.analyze_pkgbuild(path, changed)

    assert [finding.rule_id for finding in result.findings] == ["HIST-MAINTAINER-ANNOTATION-CHANGED"]
    exported = json.dumps(result.findings[0].to_dict())
    assert "fake-secret-value" not in exported
    assert "example.invalid" not in exported
    assert "\\u001b" not in exported


def test_install_file_added_is_detected(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_PKGBUILD)
    analyzer.analyze_pkgbuild(str(pkgbuild), BASE_PKGBUILD)
    analyzer.commit_pending_snapshots(scan_level="fast_default")
    (tmp_path / ".INSTALL").write_text("post_install() { echo harmless; }\n")

    result = analyzer.analyze_pkgbuild(str(pkgbuild), BASE_PKGBUILD)

    assert any(f.rule_id == "HIST-INSTALL-ADDED" for f in result.findings)


def test_declared_install_hook_content_change_uses_shared_exact_identity(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)
    pkgbuild = tmp_path / "PKGBUILD"
    content = BASE_PKGBUILD + "install=demo.install\n"
    pkgbuild.write_text(content, encoding="utf-8")
    hook = tmp_path / "demo.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")
    analyzer.analyze_pkgbuild(str(pkgbuild), content)
    analyzer.commit_pending_snapshots(scan_level="fast_default")
    previous = analyzer.get_snapshot("demo")

    hook.write_text("post_install() { printf 'changed'; }\n", encoding="utf-8")
    result = analyzer.analyze_pkgbuild(str(pkgbuild), content)
    current = analyzer.pending_snapshots["demo"]

    assert previous["install_file_hash"] != current["install_file_hash"]
    assert previous["install_hook_input_digest"] != current["install_hook_input_digest"]
    assert any(f.rule_id == "HIST-INSTALL-CHANGED" for f in result.findings)


def test_install_hook_target_change_is_detected_even_when_content_is_identical(tmp_path: Path):
    analyzer = HistoryAnalyzer(tmp_path / "history.db")
    pkgbuild = tmp_path / "PKGBUILD"
    first_content = BASE_PKGBUILD + "install=first.install\n"
    second_content = first_content.replace("first.install", "second.install")
    hook_content = "post_install() { :; }\n"
    (tmp_path / "first.install").write_text(hook_content, encoding="utf-8")
    (tmp_path / "second.install").write_text(hook_content, encoding="utf-8")
    pkgbuild.write_text(first_content, encoding="utf-8")
    analyzer.analyze_pkgbuild(str(pkgbuild), first_content)
    analyzer.commit_pending_snapshots(scan_level="fast_default")
    previous = analyzer.get_snapshot("demo")

    pkgbuild.write_text(second_content, encoding="utf-8")
    result = analyzer.analyze_pkgbuild(str(pkgbuild), second_content)
    current = analyzer.pending_snapshots["demo"]

    assert previous["install_file_hash"] == current["install_file_hash"]
    assert previous["install_hook_input_digest"] != current["install_hook_input_digest"]
    assert any(f.rule_id == "HIST-INSTALL-CHANGED" for f in result.findings)


def test_persisted_legacy_install_snapshot_does_not_false_positive_after_upgrade(tmp_path: Path):
    analyzer = HistoryAnalyzer(tmp_path / "history.db")
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_PKGBUILD, encoding="utf-8")
    (tmp_path / ".INSTALL").write_text("post_install() { :; }\n", encoding="utf-8")
    analyzer.analyze_pkgbuild(str(pkgbuild), BASE_PKGBUILD)
    analyzer.commit_pending_snapshots(scan_level="fast_default")
    legacy_snapshot = analyzer.get_snapshot("demo")
    legacy_snapshot.pop("install_hook_input_digest")
    legacy_snapshot.pop("install_hook_status")
    analyzer.save_snapshot("demo", legacy_snapshot)

    result = analyzer.analyze_pkgbuild(str(pkgbuild), BASE_PKGBUILD)

    assert not any(f.rule_id.startswith("HIST-INSTALL-") for f in result.findings)
    assert analyzer.pending_snapshots["demo"]["install_file_hash"] == legacy_snapshot["install_file_hash"]


def test_blocked_scan_does_not_overwrite_history_baseline(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)
    analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_PKGBUILD)
    analyzer.commit_pending_snapshots(scan_level="fast_default")

    changed = BASE_PKGBUILD.replace("pkgver=1.0", "pkgver=9.9").replace("sha256sums=(\"abc\")", "sha256sums=(\"changed\")")
    analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), changed)
    analyzer.discard_pending_snapshots()

    assert analyzer.get_snapshot("demo")["version"] == "1.0"


def test_accepted_scan_updates_history_baseline(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)
    analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_PKGBUILD)
    analyzer.commit_pending_snapshots(scan_level="fast_default")

    changed = BASE_PKGBUILD.replace("pkgver=1.0", "pkgver=1.1").replace("sha256sums=(\"abc\")", "sha256sums=(\"def\")")
    analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), changed)
    analyzer.commit_pending_snapshots(accepted_by="test_accept")

    snapshot = analyzer.get_snapshot("demo")
    assert snapshot["version"] == "1.1"
    assert snapshot["accepted_by"] == "test_accept"


def test_unaccepted_pending_first_scan_is_not_trusted_baseline(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)

    analyzer.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_PKGBUILD)

    assert analyzer.get_accepted_snapshot("demo") == {}
    assert "demo" in analyzer.pending_snapshots


def test_manual_review_snapshot_is_not_accepted_baseline(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)
    snapshot = analyzer.snapshot_from_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_PKGBUILD)
    snapshot.update({
        "scan_status": "manual_review_required",
        "required_manual_review": True,
        "manual_review_resolved": False,
    })
    analyzer.save_snapshot("demo", snapshot)

    assert analyzer.get_snapshot("demo")
    assert analyzer.get_accepted_snapshot("demo") == {}


def test_skipped_new_only_snapshot_is_not_accepted_baseline(tmp_path: Path):
    db = tmp_path / "history.db"
    analyzer = HistoryAnalyzer(db)
    snapshot = analyzer.snapshot_from_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_PKGBUILD)
    snapshot.update({
        "scan_status": "skipped_new_only",
        "scan_level": "skipped",
    })
    analyzer.save_snapshot("demo", snapshot)

    assert analyzer.get_accepted_snapshot("demo") == {}
