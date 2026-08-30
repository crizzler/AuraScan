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
