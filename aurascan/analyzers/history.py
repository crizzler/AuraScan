import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from aurascan.analyzers.base import BaseAnalyzer
from aurascan.core.models import (
    AnalysisResult,
    Confidence,
    EvidenceQuality,
    Finding,
    Phase,
    Severity,
    Source,
)


ARRAY_KEYS = ("source", "sha256sums", "validpgpkeys", "depends", "makedepends", "checkdepends", "optdepends")
FUNC_KEYS = ("prepare", "build", "check", "package")
ACCEPTED_SCAN_STATUSES = {"accepted", "forced_accepted"}
MANUAL_REVIEW_ACCEPTED_STATUS = "manual_review_accepted"


class HistoryAnalyzer(BaseAnalyzer):
    def __init__(self, db_path: Path = Path.home() / ".cache" / "aurascan" / "history.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.pending_snapshots: Dict[str, Dict[str, Any]] = {}
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshots'").fetchone()
            if existing:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(snapshots)").fetchall()}
                if "snapshot_json" not in columns:
                    legacy_name = "snapshots_legacy"
                    suffix = 1
                    while conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (legacy_name,)).fetchone():
                        suffix += 1
                        legacy_name = f"snapshots_legacy_{suffix}"
                    conn.execute(f"ALTER TABLE snapshots RENAME TO {legacy_name}")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    package_key TEXT PRIMARY KEY,
                    snapshot_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

    def _extract_metadata(self, content: str, pkgbuild_path: str = "") -> Dict[str, Any]:
        snapshot: Dict[str, Any] = {
            "package_name": "",
            "pkgbase": "",
            "version": "",
            "maintainer": "",
            "source_urls": [],
            "source_hosts": [],
            "checksums": [],
            "validpgpkeys": [],
            "depends": [],
            "makedepends": [],
            "checkdepends": [],
            "optdepends": [],
            "install_file_hash": "",
            "pkgbuild_hash": hashlib.sha256(content.encode("utf-8", "replace")).hexdigest(),
            "prepare_hash": "",
            "build_hash": "",
            "check_hash": "",
            "package_hash": "",
            "timestamp": time.time(),
        }
        if pkgbuild_path:
            install_path = Path(pkgbuild_path).with_name(".INSTALL")
            if install_path.exists():
                snapshot["install_file_hash"] = self._file_hash(install_path)

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("# maintainer:"):
                snapshot["maintainer"] = stripped.split(":", 1)[1].strip()
            for key, target in (("pkgname", "package_name"), ("pkgbase", "pkgbase"), ("pkgver", "version")):
                if stripped.startswith(f"{key}="):
                    snapshot[target] = self._parse_scalar(stripped.split("=", 1)[1])

        for key in ARRAY_KEYS:
            values = self._parse_array_assignment(content, key)
            if key == "source":
                snapshot["source_urls"] = values
                snapshot["source_hosts"] = sorted({urlparse(v).hostname or "" for v in values if "://" in v})
            elif key == "sha256sums":
                snapshot["checksums"] = values
            else:
                snapshot[key] = values

        for func_name in FUNC_KEYS:
            body = self._extract_function_body(content, func_name)
            if body:
                snapshot[f"{func_name}_hash"] = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
            snapshot[f"{func_name}_network_fetch"] = bool(re.search(r"\b(curl|wget|git\s+clone)\b", body, re.I))

        return snapshot

    def snapshot_from_pkgbuild(self, pkgbuild_path: str, content: str) -> Dict[str, Any]:
        return self._extract_metadata(content, pkgbuild_path)

    def package_key_for_snapshot(self, snapshot: Dict[str, Any]) -> str:
        return snapshot.get("pkgbase") or snapshot.get("package_name") or ""

    def analyze_pkgbuild(self, pkgbuild_path: str, content: str) -> AnalysisResult:
        findings: List[Finding] = []
        snapshot = self._extract_metadata(content, pkgbuild_path)
        package_key = self.package_key_for_snapshot(snapshot)
        if not package_key:
            return AnalysisResult(True, "No pkgname found", findings)

        previous = self.get_accepted_snapshot(package_key)
        if previous:
            findings = self._diff_snapshots(previous, snapshot, str(pkgbuild_path))
        else:
            snapshot["history_status"] = "pending_no_prior_accepted_history"
        self.pending_snapshots[package_key] = snapshot

        return AnalysisResult(not any(f.blocks_installation for f in findings), "History checked", findings)

    def commit_pending_snapshots(
        self,
        accepted_by: str = "scan_allowed",
        *,
        scan_level: str = "fast_default",
        scanner_version: str = "",
        rule_version: str = "",
        forced_accept: bool = False,
        trust_diff: Dict[str, Any] = None,
    ) -> None:
        for package_key, snapshot in list(self.pending_snapshots.items()):
            snapshot = dict(snapshot)
            snapshot.update(self._baseline_metadata(
                package_key,
                snapshot,
                scan_status="forced_accepted" if forced_accept else "accepted",
                scan_level=scan_level,
                accepted_by=accepted_by,
                scanner_version=scanner_version,
                rule_version=rule_version,
                forced_accept=forced_accept,
                trust_diff=trust_diff,
            ))
            self.save_snapshot(package_key, snapshot)
            del self.pending_snapshots[package_key]

    def discard_pending_snapshots(self) -> None:
        self.pending_snapshots.clear()

    def record_manual_review_accepted(
        self,
        pkgbuild_path: str,
        content: str,
        *,
        review_decision_id: str = "",
        scanner_version: str = "",
        rule_version: str = "",
        trust_diff: Dict[str, Any] = None,
    ) -> None:
        snapshot = self.snapshot_from_pkgbuild(pkgbuild_path, content)
        package_key = self.package_key_for_snapshot(snapshot)
        if not package_key:
            return
        snapshot.update(self._baseline_metadata(
            package_key,
            snapshot,
            scan_status=MANUAL_REVIEW_ACCEPTED_STATUS,
            scan_level=MANUAL_REVIEW_ACCEPTED_STATUS,
            accepted_by=f"review_decision:{review_decision_id}" if review_decision_id else "review_decision",
            scanner_version=scanner_version,
            rule_version=rule_version,
            required_manual_review=True,
            manual_review_resolved=True,
            trust_diff=trust_diff,
        ))
        snapshot["review_decision_id"] = review_decision_id
        self.save_snapshot(package_key, snapshot)

    def get_snapshot(self, package_key: str) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT snapshot_json FROM snapshots WHERE package_key = ?", (package_key,)).fetchone()
        return json.loads(row[0]) if row else {}

    def get_accepted_snapshot(self, package_key: str) -> Dict[str, Any]:
        snapshot = self.get_snapshot(package_key)
        return snapshot if self.is_accepted_baseline(snapshot) else {}

    def is_accepted_baseline(self, snapshot: Dict[str, Any]) -> bool:
        if not snapshot:
            return False
        if snapshot.get("blocked"):
            return False
        if snapshot.get("scan_status") == "skipped_new_only":
            return False
        if snapshot.get("scan_status") == MANUAL_REVIEW_ACCEPTED_STATUS:
            return False
        if snapshot.get("required_manual_review") and not snapshot.get("manual_review_resolved"):
            return False
        return snapshot.get("scan_status") in ACCEPTED_SCAN_STATUSES

    def save_snapshot(self, package_key: str, snapshot: Dict[str, Any]) -> None:
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            old = conn.execute("SELECT created_at FROM snapshots WHERE package_key = ?", (package_key,)).fetchone()
            created_at = old[0] if old else now
            conn.execute(
                "INSERT OR REPLACE INTO snapshots (package_key, snapshot_json, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (package_key, json.dumps(snapshot, sort_keys=True), created_at, now),
            )

    def _baseline_metadata(
        self,
        package_key: str,
        snapshot: Dict[str, Any],
        *,
        scan_status: str,
        scan_level: str,
        accepted_by: str,
        scanner_version: str = "",
        rule_version: str = "",
        blocked: bool = False,
        required_manual_review: bool = False,
        manual_review_resolved: bool = False,
        forced_accept: bool = False,
        trust_diff: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        stable_id_input = "|".join([
            package_key,
            str(snapshot.get("version", "")),
            str(snapshot.get("pkgbuild_hash", "")),
            str(now),
        ])
        return {
            "snapshot_id": hashlib.sha256(stable_id_input.encode("utf-8", "replace")).hexdigest(),
            "scan_status": scan_status,
            "scan_level": scan_level,
            "accepted_at": now if scan_status in ACCEPTED_SCAN_STATUSES else None,
            "accepted_by": accepted_by,
            "blocked": blocked,
            "required_manual_review": required_manual_review,
            "manual_review_resolved": manual_review_resolved,
            "forced_accept": forced_accept,
            "scanner_version": scanner_version,
            "rule_version": rule_version,
            "trust_diff": trust_diff or {},
        }

    def _diff_snapshots(self, old: Dict[str, Any], new: Dict[str, Any], pkgbuild_path: str) -> List[Finding]:
        findings: List[Finding] = []
        package_name = new.get("package_name") or old.get("package_name") or "unknown"
        package_version = new.get("version") or "unknown"

        def add(rule_id: str, severity: Severity, explanation: str, evidence: str, blocks: bool = False):
            findings.append(Finding(
                rule_id=rule_id,
                package_name=package_name,
                package_version=package_version,
                phase=Phase.history_diff,
                source=Source.history_analyzer,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                evidence_quality=EvidenceQuality.confirmed_history_diff,
                file_path=pkgbuild_path,
                explanation=explanation,
                recommendation="Review the package history and upstream provenance before installation.",
                blocks_installation=blocks,
                requires_manual_review=True,
                evidence_snippet=evidence,
            ))

        if old.get("maintainer") and new.get("maintainer") and old["maintainer"] != new["maintainer"]:
            add("HIST-MAINTAINER-CHANGED", Severity.MEDIUM, "Package maintainer changed.", f"{old['maintainer']} -> {new['maintainer']}")

        if not old.get("maintainer") and new.get("maintainer"):
            add("HIST-ORPHAN-ADOPTED", Severity.MEDIUM, "Previously unmaintained package appears adopted.", new["maintainer"])

        if old.get("source_urls") != new.get("source_urls"):
            add("HIST-SOURCE-URL-CHANGED", Severity.MEDIUM, "Source URL list changed.", f"{old.get('source_urls', [])} -> {new.get('source_urls', [])}")

        if old.get("source_hosts") != new.get("source_hosts"):
            severity = Severity.HIGH if self._looks_like_random_fork(new.get("source_hosts", []), new.get("source_urls", [])) else Severity.MEDIUM
            add("HIST-SOURCE-HOST-CHANGED", severity, "Source host changed.", f"{old.get('source_hosts', [])} -> {new.get('source_hosts', [])}")

        if old.get("checksums") and old.get("checksums") != new.get("checksums"):
            add("HIST-CHECKSUM-CHANGED", Severity.MEDIUM, "Source checksum list changed.", "checksum values differ")

        if old.get("checksums") and any(v.upper() == "SKIP" for v in new.get("checksums", [])):
            add("HIST-CHECKSUM-WEAKENED", Severity.HIGH, "Checksum verification was weakened.", str(new.get("checksums", [])))

        if old.get("validpgpkeys") and not new.get("validpgpkeys"):
            add("HIST-PGP-REMOVED", Severity.HIGH, "validpgpkeys was removed.", str(old.get("validpgpkeys")))

        for dep_key in ("depends", "makedepends", "checkdepends", "optdepends"):
            old_deps = set(old.get(dep_key, []))
            new_deps = set(new.get(dep_key, []))
            for dep in sorted(new_deps - old_deps):
                add(f"HIST-{dep_key.upper()}-ADDED", Severity.MEDIUM, f"{dep_key} added dependency.", dep)

        if not old.get("install_file_hash") and new.get("install_file_hash"):
            add("HIST-INSTALL-ADDED", Severity.HIGH, ".install hook was added.", new["install_file_hash"])
        elif old.get("install_file_hash") != new.get("install_file_hash") and new.get("install_file_hash"):
            add("HIST-INSTALL-CHANGED", Severity.MEDIUM, ".install hook changed.", "install file hash changed")

        for func_name in FUNC_KEYS:
            old_hash = old.get(f"{func_name}_hash")
            new_hash = new.get(f"{func_name}_hash")
            if old_hash and new_hash and old_hash != new_hash:
                add(f"HIST-{func_name.upper()}-CHANGED", Severity.MEDIUM, f"{func_name}() changed.", "function hash changed")
            if not old.get(f"{func_name}_network_fetch") and new.get(f"{func_name}_network_fetch"):
                add(f"HIST-{func_name.upper()}-NEW-NETWORK", Severity.HIGH, f"Network fetch newly appears in {func_name}().", func_name)

        high_signal = sum(1 for f in findings if f.severity == Severity.HIGH)
        if high_signal >= 2 and len(findings) >= 3:
            add("HIST-COMBINED-SUSPICIOUS-CHANGE", Severity.HIGH, "Multiple supply-chain history anomalies occurred together.", f"{len(findings)} history findings")

        return findings

    def _parse_scalar(self, raw: str) -> str:
        return raw.strip().strip("'\"()")

    def _parse_array_assignment(self, content: str, key: str) -> List[str]:
        match = re.search(rf"^{key}=\((.*?)\)", content, re.M | re.S)
        if match:
            return re.findall(r"""['"]?([^'"\s()]+)['"]?""", match.group(1))
        match = re.search(rf"^{key}=([^\n]+)", content, re.M)
        if match:
            return [self._parse_scalar(match.group(1))]
        return []

    def _extract_function_body(self, content: str, name: str) -> str:
        match = re.search(rf"^{name}\s*\(\)\s*\{{(?P<body>.*?)^\}}", content, re.M | re.S)
        return match.group("body") if match else ""

    def _file_hash(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _looks_like_random_fork(self, hosts: List[str], urls: List[str]) -> bool:
        joined = " ".join(hosts + urls).lower()
        return any(marker in joined for marker in ("raw.githubusercontent.com", "gist.github.com", "mirror", "fork"))
