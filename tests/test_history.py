from pathlib import Path

from aurascan.analyzers.history import HistoryAnalyzer


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


def test_maintainer_source_and_pgp_change_emit_manual_review_findings(tmp_path: Path):
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

    assert "HIST-MAINTAINER-CHANGED" in rule_ids
    assert "HIST-SOURCE-HOST-CHANGED" in rule_ids
    assert "HIST-PGP-REMOVED" in rule_ids
    assert "HIST-BUILD-NEW-NETWORK" in rule_ids
    assert all(f.requires_manual_review for f in result.findings)
    assert not any(f.blocks_installation for f in result.findings)


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
