"""Consent-gated capture and export of human review adjudications.

AuraScan already records the review decisions an operator makes at the makepkg
handoff. This module adds the two things that were missing before any of that
could support model work:

1. An immutable, append-only, retention-bounded adjudication log that binds a
   human judgment -- or records explicitly that no judgment was made -- to the
   exact content hashes and the exact finding set that was reviewed.
2. A per-purpose consent gate. Nothing leaves the private state directory as a
   corpus candidate until an operator grants consent for one specific purpose.

Boundaries this module keeps on purpose:

* Capture is local and best-effort. A log that cannot be written never blocks a
  scan, a review acceptance, or a package operation.
* Research eligibility is off by default and is never implied. Absent consent,
  export refuses and says why; it never falls back to exporting something.
* An export writes candidates only. It cannot admit data, grant rights, choose
  a split, or train anything: every candidate is written with
  ``partition: quarantine``, ``admission: not_admitted`` and unresolved rights.
* Raw package bytes, host paths and free-text operator notes are never
  exported. Candidates carry content hashes and review metadata only, so the
  separate offline intake step remains the only place bytes can be bound.
* No network, no model, no subprocess, and no reading of AI credentials.
"""

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


EVIDENCE_SCHEMA = "aurascan-research-evidence/1.0"
CONSENT_SCHEMA = "aurascan-research-evidence-consent/1.0"
CANDIDATE_SCHEMA = "aurascan-research-evidence-candidates/1.0"
EVIDENCE_DIRNAME = "research-evidence"
LOG_FILENAME = "adjudications.jsonl"
CONSENT_FILENAME = "consent.json"
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_LOG_RECORDS = 5_000
MAX_CANDIDATES = 2_000
MAX_FINDINGS_PER_RECORD = 64
MAX_TEXT = 256
RETENTION_DAYS = 365

# An operator judgment is a bounded choice, never free text. Absence of a label
# is the default and is not a training target.
LABEL_UNLABELED = ""
ADJUDICATION_LABELS = (
    "benign_false_positive",
    "benign_expected_behavior",
    "suspicious_unconfirmed",
    "confirmed_malicious",
)
LABEL_MEANINGS = {
    "benign_false_positive": "the flagged behavior is not a real threat for this package",
    "benign_expected_behavior": "the behavior is expected for this package class",
    "suspicious_unconfirmed": "needs escalation; not a confirmed threat",
    "confirmed_malicious": "the operator confirmed a real malicious behavior",
}
# Purposes follow the research contract's rights dimensions.
CONSENT_PURPOSES = ("analysis", "training", "commercial_training", "redistribution")
_GRANTED_STATEMENT = (
    "Operator consent recorded for one named purpose. This record grants no "
    "rights, admits no data, and cannot be inherited by another purpose."
)
_RIGHTS_UNRESOLVED = {
    "analysis": "unresolved",
    "training": "unresolved",
    "commercial_training": "unresolved",
    "redistribution": "unresolved",
}


class EvidenceError(ValueError):
    """A fixed, secret-free research-evidence contract failure."""


@dataclass
class AdjudicationRecord:
    adjudication_id: str
    decided_at: str
    decision_id: str
    label: str
    supersedes: str = ""
    scan_fingerprint: str = ""
    package_base_hash: str = ""
    pkgbuild_hash: str = ""
    install_hook_hashes: List[str] = field(default_factory=list)
    source_metadata_hash: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    scanner_version: str = ""
    rule_version: str = ""
    prompt_version: str = ""
    scan_config_hash: str = ""
    intelligence_identity: str = ""
    decision_status: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": EVIDENCE_SCHEMA,
            "adjudication_id": self.adjudication_id,
            "decided_at": self.decided_at,
            "supersedes": self.supersedes,
            "decision_id": self.decision_id,
            "decision_status": self.decision_status,
            "label": self.label,
            "label_meaning": LABEL_MEANINGS.get(self.label, ""),
            "label_source": "human_review" if self.label else "none",
            "scan_fingerprint": self.scan_fingerprint,
            "package_base_hash": self.package_base_hash,
            "pkgbuild_hash": self.pkgbuild_hash,
            "install_hook_hashes": list(self.install_hook_hashes),
            "source_metadata_hash": self.source_metadata_hash,
            "findings": list(self.findings),
            "scanner_version": self.scanner_version,
            "rule_version": self.rule_version,
            "prompt_version": self.prompt_version,
            "scan_config_hash": self.scan_config_hash,
            "intelligence_identity": self.intelligence_identity,
        }


def evidence_root(review_db_path: Path) -> Path:
    """Place evidence beside the review decisions it references."""

    return Path(review_db_path).parent / EVIDENCE_DIRNAME


def _text(value: object, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        return ""
    return value


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _enum_text(value: object, limit: int = 64) -> str:
    """Render a plain value or enum member without leaking its repr class."""

    inner = getattr(value, "value", None)
    return _text(inner if isinstance(inner, str) else str(value), limit)


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _prepare_directory(root: Path) -> int:
    """Return an open directory descriptor, refusing links and foreign owners."""

    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise EvidenceError("research-evidence directory is unavailable") from exc
    try:
        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise EvidenceError("research-evidence directory is not a safe directory") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise EvidenceError("research-evidence directory is not a private owned directory")
        if info.st_mode & 0o077:
            os.fchmod(fd, 0o700)
    except OSError as exc:
        os.close(fd)
        raise EvidenceError("research-evidence directory could not be verified") from exc
    return fd


def _read_private_file(directory_fd: int, name: str, limit: int) -> Optional[bytes]:
    """Read a bounded, regular, owner-controlled file without following links."""

    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EvidenceError("research-evidence file is not a safe regular file") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise EvidenceError("research-evidence file is not a private owned regular file")
        if info.st_size > limit:
            raise EvidenceError("research-evidence file exceeds its bound")
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _append_private_file(directory_fd: int, name: str, payload: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600,
                 dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise EvidenceError("research-evidence log is not a private owned regular file")
        os.write(fd, payload)
    finally:
        os.close(fd)


def _write_private_file(directory_fd: int, name: str, payload: bytes) -> None:
    """Replace a private state file through a bounded temporary file."""

    temporary = name + ".new"
    try:
        os.unlink(temporary, dir_fd=directory_fd)
    except FileNotFoundError:
        pass
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                 dir_fd=directory_fd)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)


def read_adjudications(root: Path) -> Tuple[List[Dict[str, Any]], str]:
    """Return bounded adjudication records, fail closed on malformed content."""

    directory_fd = _prepare_directory(Path(root))
    try:
        raw = _read_private_file(directory_fd, LOG_FILENAME, MAX_LOG_BYTES)
    finally:
        os.close(directory_fd)
    if raw is None:
        return [], ""
    records: List[Dict[str, Any]] = []
    for line in raw.decode("utf-8", "strict").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (ValueError, UnicodeError) as exc:
            raise EvidenceError("research-evidence log is malformed") from exc
        if not isinstance(record, dict) or record.get("schema") != EVIDENCE_SCHEMA:
            raise EvidenceError("research-evidence log record is unsupported")
        records.append(record)
    if len(records) > MAX_LOG_RECORDS:
        raise EvidenceError("research-evidence log exceeds its record bound")
    return records, ""


def append_adjudication(root: Path, record: AdjudicationRecord) -> Dict[str, Any]:
    """Append one immutable adjudication record, pruning oldest entries first."""

    if record.label and record.label not in ADJUDICATION_LABELS:
        raise EvidenceError("research-evidence label is unsupported")
    payload = record.to_dict()
    encoded = (json.dumps(payload, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")) + "\n").encode("ascii")
    root = Path(root)
    directory_fd = _prepare_directory(root)
    try:
        existing = _read_private_file(directory_fd, LOG_FILENAME, MAX_LOG_BYTES) or b""
        lines = [line for line in existing.decode("utf-8", "replace").splitlines() if line.strip()]
        for line in lines:
            if _line_adjudication_id(line) == record.adjudication_id:
                # Immutability: an identical record is never rewritten.
                return payload
        lines.append(encoded.decode("ascii").strip())
        if len(lines) > MAX_LOG_RECORDS:
            lines = lines[-MAX_LOG_RECORDS:]
        _write_private_file(directory_fd, LOG_FILENAME, ("\n".join(lines) + "\n").encode("ascii"))
    finally:
        os.close(directory_fd)
    return payload


def _line_adjudication_id(line: str) -> str:
    try:
        value = json.loads(line)
    except ValueError:
        return ""
    if not isinstance(value, dict):
        return ""
    return str(value.get("adjudication_id", ""))


def adjudication_record(decision, label: str, *, now: Optional[str] = None,
                        previous: str = "", intelligence_identity: str = "") -> AdjudicationRecord:
    """Build a bounded record from a review decision; never copies free text."""

    decided_at = now or _utc_now()
    label = label if label in ADJUDICATION_LABELS else LABEL_UNLABELED
    findings: List[Dict[str, Any]] = []
    for finding_id in list(getattr(decision, "finding_ids", []))[:MAX_FINDINGS_PER_RECORD]:
        findings.append({"finding_id": _text(str(finding_id), 128)})
    identity = "|".join([
        str(getattr(decision, "decision_id", "")), decided_at, label, previous,
    ])
    return AdjudicationRecord(
        adjudication_id=_digest(identity),
        decided_at=decided_at,
        decision_id=_text(str(getattr(decision, "decision_id", "")), 128),
        label=label,
        supersedes=previous,
        scan_fingerprint=_text(str(getattr(decision, "scan_fingerprint", "")), 128),
        package_base_hash=_digest(str(getattr(decision, "package_base", ""))),
        pkgbuild_hash=_text(str(getattr(decision, "pkgbuild_hash", "")), 128),
        install_hook_hashes=[
            _text(str(value), 128)
            for value in list(getattr(decision, "install_hook_hashes", []))[:16]
        ],
        source_metadata_hash=_text(str(getattr(decision, "source_metadata_hash", "")), 128),
        findings=findings,
        scanner_version=_text(str(getattr(decision, "scanner_version", "")), 64),
        rule_version=_text(str(getattr(decision, "rule_version", "")), 64),
        prompt_version=_text(str(getattr(decision, "prompt_version", "")), 64),
        scan_config_hash=_text(str(getattr(decision, "scan_config_hash", "")), 128),
        intelligence_identity=_text(intelligence_identity, 128),
        decision_status=_enum_text(getattr(decision, "decision_status", "")),
    )


def read_consent(root: Path) -> Tuple[Dict[str, Any], str]:
    directory_fd = _prepare_directory(Path(root))
    try:
        raw = _read_private_file(directory_fd, CONSENT_FILENAME, 64 * 1024)
    finally:
        os.close(directory_fd)
    if raw is None:
        return {"schema": CONSENT_SCHEMA, "purposes": {}, "unsupported": ""}, ""
    try:
        data = json.loads(raw.decode("utf-8", "strict"))
    except (ValueError, UnicodeError):
        return {"schema": CONSENT_SCHEMA, "purposes": {}}, "consent state is unreadable"
    if not isinstance(data, dict) or data.get("schema") != CONSENT_SCHEMA:
        return {"schema": CONSENT_SCHEMA, "purposes": {}}, "consent state is unsupported"
    purposes = data.get("purposes")
    if not isinstance(purposes, dict):
        return {"schema": CONSENT_SCHEMA, "purposes": {}}, "consent state is unsupported"
    return data, ""


def grant_consent(root: Path, purpose: str, *, confirm: str, operator: str = "") -> Dict[str, Any]:
    """Record one per-purpose consent; the caller must echo the exact purpose."""

    if purpose not in CONSENT_PURPOSES:
        raise EvidenceError("research-evidence consent purpose is unsupported")
    if confirm != purpose:
        raise EvidenceError("research-evidence consent requires the exact purpose confirmation")
    data, error = read_consent(Path(root))
    if error:
        raise EvidenceError(error)
    purposes = dict(data.get("purposes") or {})
    purposes[purpose] = {
        "purpose": purpose,
        "granted_at": _utc_now(),
        "granted_by": _text(operator, 128),
        "statement": _GRANTED_STATEMENT,
        "rights_granted": "none",
    }
    updated = {"schema": CONSENT_SCHEMA, "purposes": purposes}
    directory_fd = _prepare_directory(Path(root))
    try:
        _write_private_file(directory_fd, CONSENT_FILENAME,
                            (json.dumps(updated, sort_keys=True, indent=2) + "\n").encode("ascii"))
    finally:
        os.close(directory_fd)
    return purposes[purpose]


def revoke_consent(root: Path, purpose: str) -> bool:
    if purpose not in CONSENT_PURPOSES:
        raise EvidenceError("research-evidence consent purpose is unsupported")
    data, error = read_consent(Path(root))
    if error:
        raise EvidenceError(error)
    purposes = dict(data.get("purposes") or {})
    if purpose not in purposes:
        return False
    del purposes[purpose]
    updated = {"schema": CONSENT_SCHEMA, "purposes": purposes}
    directory_fd = _prepare_directory(Path(root))
    try:
        _write_private_file(directory_fd, CONSENT_FILENAME,
                            (json.dumps(updated, sort_keys=True, indent=2) + "\n").encode("ascii"))
    finally:
        os.close(directory_fd)
    return True


def status(root: Path) -> Dict[str, Any]:
    """Report capture state and why an export is or is not possible."""

    data, consent_error = read_consent(Path(root))
    try:
        records, log_error = read_adjudications(Path(root))
    except EvidenceError:
        records, log_error = [], "adjudication log is malformed or unsafe"
    labeled = [record for record in records if record.get("label")]
    return {
        "schema": EVIDENCE_SCHEMA,
        "records": len(records),
        "labeled_records": len(labeled),
        "unlabeled_records": len(records) - len(labeled),
        "labels": {
            label: len([item for item in records if item.get("label") == label])
            for label in ADJUDICATION_LABELS
        },
        "consent": {purpose: bool((data.get("purposes") or {}).get(purpose))
                    for purpose in CONSENT_PURPOSES},
        "consent_error": consent_error,
        "log_error": log_error,
        "capture": "local_only",
        "admission": "not_admitted",
        "retention_days": RETENTION_DAYS,
    }


def _candidate(record: Dict[str, Any]) -> Dict[str, Any]:
    """Project one adjudication into a quarantine corpus candidate."""

    findings = []
    for finding in list(record.get("findings") or [])[:MAX_FINDINGS_PER_RECORD]:
        if not isinstance(finding, dict):
            continue
        findings.append({
            "finding_id": _text(str(finding.get("finding_id", "")), 128),
        })
    return {
        "candidate_id": _text(str(record.get("adjudication_id", "")), 128),
        "schema": CANDIDATE_SCHEMA,
        "partition": "quarantine",
        "admission": "not_admitted",
        "derivation_family": _text(str(record.get("package_base_hash", "")), 128),
        "label": record.get("label", ""),
        "label_meaning": LABEL_MEANINGS.get(record.get("label", ""), ""),
        "label_source": "human_review",
        "supersedes": _text(str(record.get("supersedes", "")), 128),
        "decided_at": _text(str(record.get("decided_at", "")), 64),
        "scan_fingerprint": _text(str(record.get("scan_fingerprint", "")), 128),
        "content_binding": "hash_only",
        "content_hashes": {
            "pkgbuild": _text(str(record.get("pkgbuild_hash", "")), 128),
            "install_hooks": [
                _text(str(value), 128)
                for value in list(record.get("install_hook_hashes") or [])[:16]
            ],
            "source_metadata": _text(str(record.get("source_metadata_hash", "")), 128),
        },
        "findings": findings,
        "provenance": {
            "scanner_version": _text(str(record.get("scanner_version", "")), 64),
            "rule_version": _text(str(record.get("rule_version", "")), 64),
            "prompt_version": _text(str(record.get("prompt_version", "")), 64),
            "scan_config_hash": _text(str(record.get("scan_config_hash", "")), 128),
            "intelligence_identity": _text(str(record.get("intelligence_identity", "")), 128),
        },
        "rights": dict(_RIGHTS_UNRESOLVED),
        "requires_offline_intake": True,
        "excluded": "raw package bytes, host paths, operator identity and free-text notes",
    }


def export_candidates(root: Path, purpose: str, out_path: Path) -> Dict[str, Any]:
    """Write consented, labeled adjudications as quarantine candidates."""

    if purpose not in CONSENT_PURPOSES:
        raise EvidenceError("research-evidence export purpose is unsupported")
    consent, consent_error = read_consent(Path(root))
    if consent_error:
        raise EvidenceError(consent_error)
    granted = (consent.get("purposes") or {}).get(purpose)
    if not granted:
        raise EvidenceError(
            "no recorded consent for this purpose; run the consent command first"
        )
    records, log_error = read_adjudications(Path(root))
    if log_error:
        raise EvidenceError(log_error)
    # The newest record for a decision wins, so a revocation or a relabel
    # withdraws the earlier judgment instead of leaving a stale target.
    latest: Dict[str, Dict[str, Any]] = {}
    for record in records:
        latest[str(record.get("decision_id", ""))] = record
    candidates = [_candidate(record) for record in latest.values()
                  if record.get("label") in ADJUDICATION_LABELS]
    excluded = len(latest) - len(candidates)
    if not candidates:
        raise EvidenceError("no labeled adjudications are available to export")
    candidates.sort(key=lambda item: item["candidate_id"])
    candidates = candidates[:MAX_CANDIDATES]
    document = {
        "schema": CANDIDATE_SCHEMA,
        "generated_at": _utc_now(),
        "purpose": purpose,
        "consent": {
            "purpose": granted.get("purpose", ""),
            "granted_at": granted.get("granted_at", ""),
            "statement": granted.get("statement", ""),
            "rights_granted": "none",
        },
        "counts": {"candidates": len(candidates), "excluded_unlabeled": excluded},
        "admission": "not_admitted",
        "partition": "quarantine",
        "rights": dict(_RIGHTS_UNRESOLVED),
        "notes": [
            "Candidates only: nothing here is admitted, labeled as ground truth, or usable for training yet.",
            "Rights remain unresolved for every purpose; admission review decides independently.",
            "Bytes are bound separately during offline intake under its own consent.",
        ],
        "candidates": candidates,
    }
    encoded = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("ascii")
    out_path = Path(out_path)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(out_path),
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, encoded)
        finally:
            os.close(fd)
    except OSError as exc:
        raise EvidenceError("research-evidence export destination is not writable") from exc
    return {
        "path": str(out_path),
        "digest": hashlib.sha256(encoded).hexdigest(),
        "candidates": len(candidates),
        "excluded_unlabeled": excluded,
        "purpose": purpose,
        "admission": "not_admitted",
    }
