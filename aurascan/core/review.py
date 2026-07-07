import getpass
import hashlib
import json
import os
import re
import shlex
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class ReviewDecisionStatus(Enum):
    accepted_once = "accepted_once"
    accepted_persistent_for_exact_scan = "accepted_persistent_for_exact_scan"
    revoked = "revoked"
    expired = "expired"


class ReviewScope(Enum):
    exact_scan = "exact_scan"
    exact_package_version = "exact_package_version"
    exact_finding_set = "exact_finding_set"


@dataclass
class ScanFingerprint:
    package_name: str = "unknown"
    package_base: str = ""
    package_version: str = "unknown"
    pkgbuild_hash: str = ""
    install_hook_hashes: List[str] = field(default_factory=list)
    source_metadata_hash: str = ""
    scan_fingerprint: str = ""
    finding_ids: List[str] = field(default_factory=list)
    finding_fingerprints: List[str] = field(default_factory=list)
    scanner_version: str = ""
    rule_version: str = ""
    prompt_version: str = ""
    scan_config_hash: str = ""
    acceptance_scope: ReviewScope = ReviewScope.exact_scan

    @property
    def review_token(self) -> str:
        material = "|".join([
            self.scan_fingerprint,
            ",".join(self.finding_fingerprints),
            self.package_name,
            self.package_version,
            self.scan_config_hash,
        ])
        return "arv-" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:24]


@dataclass
class ReviewDecision:
    decision_id: str
    review_token: str
    package_name: str
    package_base: str
    package_version: str
    pkgbuild_hash: str
    install_hook_hashes: List[str]
    source_metadata_hash: str
    scan_fingerprint: str
    finding_ids: List[str]
    finding_fingerprints: List[str]
    accepted_at: float
    accepted_by: str
    decision_status: ReviewDecisionStatus
    acceptance_scope: ReviewScope
    reason: str = ""
    scanner_version: str = ""
    rule_version: str = ""
    prompt_version: str = ""
    scan_config_hash: str = ""
    expires_at: Optional[float] = None
    one_time: bool = True
    used_at: Optional[float] = None
    revoked_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "review_token": self.review_token,
            "package_name": self.package_name,
            "package_base": self.package_base,
            "package_version": self.package_version,
            "pkgbuild_hash": self.pkgbuild_hash,
            "install_hook_hashes": list(self.install_hook_hashes),
            "source_metadata_hash": self.source_metadata_hash,
            "scan_fingerprint": self.scan_fingerprint,
            "finding_ids": list(self.finding_ids),
            "finding_fingerprints": list(self.finding_fingerprints),
            "accepted_at": self.accepted_at,
            "accepted_by": self.accepted_by,
            "decision_status": self.decision_status.value,
            "acceptance_scope": self.acceptance_scope.value,
            "reason": self.reason,
            "scanner_version": self.scanner_version,
            "rule_version": self.rule_version,
            "prompt_version": self.prompt_version,
            "scan_config_hash": self.scan_config_hash,
            "expires_at": self.expires_at,
            "one_time": self.one_time,
            "used_at": self.used_at,
            "revoked_at": self.revoked_at,
        }

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return self.expires_at is not None and self.expires_at <= now

    def effective_status(self, now: Optional[float] = None) -> str:
        if self.decision_status == ReviewDecisionStatus.revoked:
            return ReviewDecisionStatus.revoked.value
        if self.is_expired(now):
            return ReviewDecisionStatus.expired.value
        if self.one_time and self.used_at is not None:
            return "used"
        return self.decision_status.value

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "ReviewDecision":
        data = dict(row)
        return cls(
            decision_id=data["decision_id"],
            review_token=data["review_token"],
            package_name=data["package_name"],
            package_base=data["package_base"],
            package_version=data["package_version"],
            pkgbuild_hash=data["pkgbuild_hash"],
            install_hook_hashes=json.loads(data["install_hook_hashes"] or "[]"),
            source_metadata_hash=data["source_metadata_hash"],
            scan_fingerprint=data["scan_fingerprint"],
            finding_ids=json.loads(data["finding_ids"] or "[]"),
            finding_fingerprints=json.loads(data["finding_fingerprints"] or "[]"),
            accepted_at=float(data["accepted_at"]),
            accepted_by=data["accepted_by"],
            decision_status=ReviewDecisionStatus(data["decision_status"]),
            acceptance_scope=ReviewScope(data["acceptance_scope"]),
            reason=data["reason"],
            scanner_version=data["scanner_version"],
            rule_version=data["rule_version"],
            prompt_version=data["prompt_version"],
            scan_config_hash=data["scan_config_hash"],
            expires_at=data["expires_at"],
            one_time=bool(data["one_time"]),
            used_at=data["used_at"],
            revoked_at=data.get("revoked_at"),
        )


class ReviewDecisionStore:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path is not None else Path.home() / ".local" / "share" / "aurascan" / "review_decisions.db"
        self._prepare_storage_path()
        self._init_db()
        self._harden_storage_permissions()

    def _prepare_storage_path(self) -> None:
        self.db_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.db_path.exists():
            return
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        try:
            fd = os.open(self.db_path, flags, 0o600)
        except FileExistsError:
            return
        else:
            os.close(fd)

    def _harden_storage_permissions(self) -> None:
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass
        if self.db_path.parent.name == "aurascan":
            try:
                os.chmod(self.db_path.parent, 0o700)
            except OSError:
                pass

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS review_decisions (
                    decision_id TEXT PRIMARY KEY,
                    review_token TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_base TEXT NOT NULL,
                    package_version TEXT NOT NULL,
                    pkgbuild_hash TEXT NOT NULL,
                    install_hook_hashes TEXT NOT NULL,
                    source_metadata_hash TEXT NOT NULL,
                    scan_fingerprint TEXT NOT NULL,
                    finding_ids TEXT NOT NULL,
                    finding_fingerprints TEXT NOT NULL,
                    accepted_at REAL NOT NULL,
                    accepted_by TEXT NOT NULL,
                    decision_status TEXT NOT NULL,
                    acceptance_scope TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    scanner_version TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    scan_config_hash TEXT NOT NULL,
                    expires_at REAL,
                    one_time INTEGER NOT NULL,
                    used_at REAL,
                    revoked_at REAL
                )
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(review_decisions)").fetchall()}
            if "revoked_at" not in columns:
                conn.execute("ALTER TABLE review_decisions ADD COLUMN revoked_at REAL")

    def record_acceptance(
        self,
        fingerprint: ScanFingerprint,
        *,
        reason: str = "",
        remember: bool = False,
        accepted_by: Optional[str] = None,
        now: Optional[float] = None,
        expires_at: Optional[float] = None,
    ) -> ReviewDecision:
        now = time.time() if now is None else now
        decision_id = hashlib.sha256(
            f"{fingerprint.review_token}|{fingerprint.scan_fingerprint}|{now}".encode("utf-8", "replace")
        ).hexdigest()
        decision = ReviewDecision(
            decision_id=decision_id,
            review_token=fingerprint.review_token,
            package_name=fingerprint.package_name,
            package_base=fingerprint.package_base,
            package_version=fingerprint.package_version,
            pkgbuild_hash=fingerprint.pkgbuild_hash,
            install_hook_hashes=list(fingerprint.install_hook_hashes),
            source_metadata_hash=fingerprint.source_metadata_hash,
            scan_fingerprint=fingerprint.scan_fingerprint,
            finding_ids=list(fingerprint.finding_ids),
            finding_fingerprints=list(fingerprint.finding_fingerprints),
            accepted_at=now,
            accepted_by=accepted_by or _accepted_by(),
            decision_status=(
                ReviewDecisionStatus.accepted_persistent_for_exact_scan
                if remember
                else ReviewDecisionStatus.accepted_once
            ),
            acceptance_scope=fingerprint.acceptance_scope,
            reason=reason,
            scanner_version=fingerprint.scanner_version,
            rule_version=fingerprint.rule_version,
            prompt_version=fingerprint.prompt_version,
            scan_config_hash=fingerprint.scan_config_hash,
            expires_at=expires_at,
            one_time=not remember,
            used_at=now if not remember else None,
        )
        self._save(decision)
        return decision

    def decision_for_token(self, review_token: str) -> Optional[ReviewDecision]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM review_decisions WHERE review_token = ? ORDER BY accepted_at DESC LIMIT 1",
                (review_token,),
            ).fetchone()
        return ReviewDecision.from_row(row) if row else None

    def decision_by_id(self, decision_id: str) -> Optional[ReviewDecision]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM review_decisions WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()
        return ReviewDecision.from_row(row) if row else None

    def list_decisions(
        self,
        *,
        package_name: str = "",
        status: str = "",
        now: Optional[float] = None,
    ) -> List[ReviewDecision]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM review_decisions ORDER BY accepted_at DESC").fetchall()
        decisions = [ReviewDecision.from_row(row) for row in rows]
        if package_name:
            decisions = [item for item in decisions if item.package_name == package_name]
        if status:
            decisions = [item for item in decisions if item.effective_status(now) == status]
        return decisions

    def revoke(self, decision_id: str, *, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE review_decisions SET decision_status = ?, revoked_at = ? WHERE decision_id = ?",
                (ReviewDecisionStatus.revoked.value, now, decision_id),
            )
            return cur.rowcount > 0

    def _save(self, decision: ReviewDecision) -> None:
        data = decision.to_dict()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO review_decisions (
                    decision_id, review_token, package_name, package_base,
                    package_version, pkgbuild_hash, install_hook_hashes,
                    source_metadata_hash, scan_fingerprint, finding_ids,
                    finding_fingerprints, accepted_at, accepted_by,
                    decision_status, acceptance_scope, reason, scanner_version,
                    rule_version, prompt_version, scan_config_hash, expires_at,
                    one_time, used_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["decision_id"],
                    data["review_token"],
                    data["package_name"],
                    data["package_base"],
                    data["package_version"],
                    data["pkgbuild_hash"],
                    json.dumps(data["install_hook_hashes"], sort_keys=True),
                    data["source_metadata_hash"],
                    data["scan_fingerprint"],
                    json.dumps(data["finding_ids"], sort_keys=True),
                    json.dumps(data["finding_fingerprints"], sort_keys=True),
                    data["accepted_at"],
                    data["accepted_by"],
                    data["decision_status"],
                    data["acceptance_scope"],
                    data["reason"],
                    data["scanner_version"],
                    data["rule_version"],
                    data["prompt_version"],
                    data["scan_config_hash"],
                    data["expires_at"],
                    1 if data["one_time"] else 0,
                    data["used_at"],
                    data["revoked_at"],
                ),
            )


HARD_BLOCKER_RULE_IDS = {
    "SOURCE-CHECKSUM-MISMATCH",
    "SIGNATURE-INVALID",
    "SIGNATURE-FINGERPRINT-MISMATCH",
    "ARCHIVE-PATH-TRAVERSAL",
    "ARCHIVE-SYMLINK-ESCAPE",
    "ARCHIVE-HARDLINK-ESCAPE",
    "ARCHIVE-TOO-MANY-FILES",
    "ARCHIVE-OVERSIZED",
    "ARCHIVE-NESTED-DEPTH",
    "CLAMAV-HIT",
    "CLAMAV-FOUND",
    "PKG-EXTRACT-ERR",
}

HARD_BLOCKER_PREFIXES = ("CLAMAV", "ARCHIVE-")


def get_non_acceptance_blockers(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    blockers = []
    for finding in _findings(report):
        if _is_hard_blocker(finding):
            blockers.append(finding)
    return blockers


def get_manual_review_acceptance_candidates(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    blockers = {id(item) for item in get_non_acceptance_blockers(report)}
    candidates = []
    for finding in _findings(report):
        if id(finding) in blockers:
            continue
        if finding.get("requires_manual_review") and not finding.get("blocks_installation"):
            candidates.append(finding)
    return candidates


def is_review_acceptance_eligible(report: Dict[str, Any]) -> bool:
    return bool(get_manual_review_acceptance_candidates(report)) and not get_non_acceptance_blockers(report)


def build_scan_fingerprint(
    report: Dict[str, Any],
    pkgbuild_path: Path,
    *,
    scanner_version: str = "",
    rule_version: str = "",
    prompt_version: str = "",
    scan_config_hash: str = "",
    acceptance_scope: ReviewScope = ReviewScope.exact_scan,
) -> ScanFingerprint:
    metadata = report.get("package_metadata") or {}
    findings = get_manual_review_acceptance_candidates(report)
    finding_ids = [str(item.get("finding_id") or "") for item in findings if item.get("finding_id")]
    finding_fingerprints = sorted(_finding_fingerprint(item) for item in findings)
    pkgbuild_hash = _file_hash(pkgbuild_path)
    install_hook_hashes = _install_hook_hashes(pkgbuild_path)
    source_metadata_hash = _source_metadata_hash(report)
    material = {
        "acceptance_scope": acceptance_scope.value,
        "finding_fingerprints": finding_fingerprints,
        "install_hook_hashes": install_hook_hashes,
        "package_base": metadata.get("pkgbase") or "",
        "package_name": metadata.get("name") or "unknown",
        "package_version": metadata.get("version") or "unknown",
        "pkgbuild_hash": pkgbuild_hash,
        "prompt_version": prompt_version,
        "rule_version": rule_version,
        "scan_config_hash": scan_config_hash,
        "scanner_version": scanner_version or report.get("scanner_version") or "",
        "source_metadata_hash": source_metadata_hash,
    }
    scan_fingerprint = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()
    return ScanFingerprint(
        package_name=str(material["package_name"]),
        package_base=str(material["package_base"]),
        package_version=str(material["package_version"]),
        pkgbuild_hash=pkgbuild_hash,
        install_hook_hashes=install_hook_hashes,
        source_metadata_hash=source_metadata_hash,
        scan_fingerprint=scan_fingerprint,
        finding_ids=finding_ids,
        finding_fingerprints=finding_fingerprints,
        scanner_version=str(material["scanner_version"]),
        rule_version=rule_version,
        prompt_version=prompt_version,
        scan_config_hash=scan_config_hash,
        acceptance_scope=acceptance_scope,
    )


def validate_review_token(
    review_token: str,
    fingerprint: ScanFingerprint,
    store: ReviewDecisionStore,
    *,
    now: Optional[float] = None,
) -> Tuple[bool, str]:
    if review_token != fingerprint.review_token:
        return False, "token_mismatch"
    decision = store.decision_for_token(review_token)
    if decision is None:
        return True, "new_acceptance"
    now = time.time() if now is None else now
    if decision.decision_status == ReviewDecisionStatus.revoked:
        return False, "decision_revoked"
    if decision.expires_at is not None and decision.expires_at <= now:
        return False, "decision_expired"
    if decision.one_time and decision.used_at is not None:
        return False, "one_time_acceptance_already_used"
    if decision.scan_fingerprint != fingerprint.scan_fingerprint:
        return False, "scan_fingerprint_changed"
    if sorted(decision.finding_fingerprints) != sorted(fingerprint.finding_fingerprints):
        return False, "finding_set_changed"
    return True, "existing_acceptance"


def annotate_report_for_review(
    report: Dict[str, Any],
    *,
    fingerprint: Optional[ScanFingerprint],
    blockers: Sequence[Dict[str, Any]],
    candidates: Sequence[Dict[str, Any]],
    acceptance_status: str,
    decision_id: str = "",
) -> None:
    report["review_acceptance_required"] = bool(candidates or blockers)
    report["review_acceptance_eligible"] = bool(candidates and not blockers)
    if fingerprint is not None:
        report["review_token"] = fingerprint.review_token
        report["acceptance_scope"] = fingerprint.acceptance_scope.value
        report["accepted_finding_ids"] = list(fingerprint.finding_ids)
        report["finding_fingerprints"] = list(fingerprint.finding_fingerprints)
        report["scan_fingerprint"] = fingerprint.scan_fingerprint
    if decision_id:
        report["review_decision_id"] = decision_id
    report["acceptance_status"] = acceptance_status
    report["non_acceptance_blockers"] = [
        {"rule_id": item.get("rule_id"), "severity": item.get("severity"), "source": item.get("source")}
        for item in blockers
    ]


def _findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [item for item in report.get("findings", []) if isinstance(item, dict)]


def _is_hard_blocker(finding: Dict[str, Any]) -> bool:
    rule_id = str(finding.get("rule_id") or "")
    severity = str(finding.get("severity") or "")
    source = str(finding.get("source") or "")
    if finding.get("blocks_installation"):
        return True
    if rule_id in HARD_BLOCKER_RULE_IDS:
        return True
    if rule_id.startswith(HARD_BLOCKER_PREFIXES) and severity == "CRITICAL":
        return True
    if source == "clamav":
        return True
    if source == "deterministic_rule" and severity == "CRITICAL":
        return True
    return False


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    material = {
        "rule_id": finding.get("rule_id") or "",
        "phase": finding.get("phase") or "",
        "source": finding.get("source") or "",
        "severity": finding.get("severity") or "",
        "confidence": finding.get("confidence") or "",
        "evidence_quality": finding.get("evidence_quality") or "",
        "file_path": finding.get("file_path") or "",
        "line_number": finding.get("line_number"),
        "evidence_snippet": finding.get("evidence_snippet") or "",
        "explanation": finding.get("explanation") or "",
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8", "replace")).hexdigest()


def _source_metadata_hash(report: Dict[str, Any]) -> str:
    source_findings = [
        {
            "rule_id": item.get("rule_id"),
            "severity": item.get("severity"),
            "evidence_snippet": item.get("evidence_snippet"),
        }
        for item in _findings(report)
        if str(item.get("rule_id", "")).startswith("SOURCE")
        or str(item.get("rule_id", "")).startswith("SIGNATURE")
    ]
    return hashlib.sha256(json.dumps(source_findings, sort_keys=True).encode("utf-8")).hexdigest()


def _install_hook_hashes(pkgbuild_path: Path) -> List[str]:
    try:
        content = pkgbuild_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    match = re.search(r"^\s*install\s*=\s*(?P<value>[^\n]+)", content, re.M)
    if not match:
        return []
    raw = match.group("value")
    if "$" in raw or "`" in raw:
        return []
    try:
        tokens = shlex.split(raw, comments=True, posix=True)
    except ValueError:
        return []
    hashes = []
    for token in tokens[:1]:
        rel = Path(token)
        if rel.is_absolute() or ".." in rel.parts:
            continue
        path = pkgbuild_path.parent / rel
        if path.is_file():
            hashes.append(_file_hash(path))
    return hashes


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _accepted_by() -> str:
    try:
        return getpass.getuser()
    except (ImportError, KeyError, OSError):
        return os.environ.get("USER", "unknown")
