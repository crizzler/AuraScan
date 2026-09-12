"""Bounded runtime intelligence data; this is not the research corpus contract.

Only application-owned matchers interpret these records. Neither references nor
record metadata grant command, network, model, or policy authority.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlsplit


SCHEMA_VERSION = "1.0"
ENGINE_CAPABILITY = "1.0"
FEED_ID = "aurascan-intelligence"
MANIFEST_FILENAME = "manifest.json"
SIGNATURE_FILENAME = "manifest.json.asc"
PAYLOAD_FILENAME = "intelligence.json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 10000
MAX_VALIDITY_DAYS = 30
MAX_CLOCK_SKEW = timedelta(minutes=5)
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}\Z")
_PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z", re.I)
_FLOOR = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){3}\Z")


class IntelligenceError(ValueError):
    """A fixed, secret-free intelligence contract or verification failure."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntelligenceError("intelligence JSON contains duplicate keys")
        result[key] = value
    return result


def _constant(_value):
    raise IntelligenceError("intelligence JSON contains a non-finite number")


def _integer(value):
    if len(value) > 20:
        raise IntelligenceError("intelligence integer exceeds its bound")
    return int(value)


def _float(_value):
    raise IntelligenceError("intelligence floating-point values are unsupported")


def strict_json(payload: bytes, limit: int) -> Dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > limit:
        raise IntelligenceError("intelligence document exceeds its byte bound")
    try:
        result = json.loads(payload.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant, parse_int=_integer, parse_float=_float)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise IntelligenceError("intelligence document is not supported strict JSON") from exc
    pending = [(result, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > 100000 or depth > 16:
            raise IntelligenceError("intelligence document exceeds its structure bound")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    if not isinstance(result, dict):
        raise IntelligenceError("intelligence document must be an object")
    return result


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise IntelligenceError("intelligence record fields are unsupported or incomplete")


def _text(value, maximum=512):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise IntelligenceError("intelligence text is missing or outside its bounds")
    return value


def _identity(value, maximum=256):
    if not isinstance(value, str) or len(value) > maximum or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+~-]*", value):
        raise IntelligenceError("intelligence record identity is malformed")
    return value


def _date(value):
    try:
        if not isinstance(value, str) or len(value) != 10 or date.fromisoformat(value).isoformat() != value:
            raise ValueError()
    except ValueError as exc:
        raise IntelligenceError("intelligence review date is malformed") from exc


def _uri(value):
    _text(value, 1024)
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None, 443):
            raise ValueError()
        if not value.isascii() or any(c.isspace() for c in value):
            raise ValueError()
    except ValueError as exc:
        raise IntelligenceError("intelligence reference is not an HTTPS source identity") from exc


def _list(value, maximum=MAX_RECORDS, nonempty=False):
    if not isinstance(value, list) or len(value) > maximum or (nonempty and not value):
        raise IntelligenceError("intelligence record collection is outside its bounds")
    return value


def _unique(values):
    if len(set(values)) != len(values):
        raise IntelligenceError("intelligence contains duplicate record identities")


def _references(value):
    for item in _list(value, 32, True):
        _uri(item)
    _unique(value)


def _rights(value):
    _keys(value, ("redistribution", "basis"))
    if value["redistribution"] != "permitted":
        raise IntelligenceError("intelligence redistribution permission is unresolved")
    _text(value["basis"])


def validate_payload(payload: bytes) -> Dict[str, Any]:
    data = strict_json(payload, MAX_PAYLOAD_BYTES)
    _keys(data, ("schema_version", "feed_id", "reviewed_at", "npm_campaigns", "vendor_advisories", "withdrawals"))
    if data["schema_version"] != SCHEMA_VERSION or data["feed_id"] != FEED_ID:
        raise IntelligenceError("intelligence payload schema or feed is unsupported")
    _date(data["reviewed_at"])
    campaign_ids = []
    record_count = 0
    for campaign in _list(data["npm_campaigns"], 256):
        _keys(campaign, ("id", "reviewed_at", "references", "rights", "packages", "payload_sha256", "malicious_domains"))
        campaign_ids.append(_identity(campaign["id"]))
        _date(campaign["reviewed_at"])
        _references(campaign["references"])
        _rights(campaign["rights"])
        names = []
        for package in _list(campaign["packages"]):
            record_count += 1
            _keys(package, ("name", "versions", "advisory_ids", "references", "broad_advisory"))
            if not isinstance(package["name"], str) or len(package["name"]) > 214 or not _PACKAGE.fullmatch(package["name"]):
                raise IntelligenceError("intelligence npm identity is malformed")
            names.append(package["name"])
            for version in _list(package["versions"], 256, True):
                exact = re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", _text(version, 128))
                if not exact or (exact.group(1) and any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in exact.group(1).split("."))):
                    raise IntelligenceError("intelligence npm release is not an exact identity")
            _unique(package["versions"])
            for advisory in _list(package["advisory_ids"], 32, True):
                _identity(advisory)
            _unique(package["advisory_ids"])
            _references(package["references"])
            if package["broad_advisory"] not in ("none", "all_versions"):
                raise IntelligenceError("intelligence npm advisory scope is unsupported")
        _unique(names)
        for digest in _list(campaign["payload_sha256"]):
            if not isinstance(digest, str) or not _HEX.fullmatch(digest):
                raise IntelligenceError("intelligence payload hash is malformed")
        _unique(campaign["payload_sha256"])
        for domain in _list(campaign["malicious_domains"]):
            if not isinstance(domain, str) or len(domain) > 253 or domain != domain.lower() or "." not in domain or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
                raise IntelligenceError("intelligence network indicator is malformed")
        _unique(campaign["malicious_domains"])
        record_count += len(campaign["payload_sha256"]) + len(campaign["malicious_domains"])
    _unique(campaign_ids)
    advisory_ids = []
    for advisory in _list(data["vendor_advisories"]):
        _keys(advisory, ("id", "cve", "package", "fixed_floor", "comparator", "known_exploited", "vendor_reference", "exploitation_reference", "reviewed_at", "rights"))
        advisory_ids.append(_identity(advisory["id"]))
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,12}", _text(advisory["cve"], 32)):
            raise IntelligenceError("intelligence CVE identity is malformed")
        if not re.fullmatch(r"[a-z0-9][a-z0-9@._+-]{0,213}", _text(advisory["package"], 214)):
            raise IntelligenceError("intelligence Arch package identity is malformed")
        if advisory["comparator"] != "chromium_four_part" or not _FLOOR.fullmatch(_text(advisory["fixed_floor"], 64)) or advisory["known_exploited"] is not True:
            raise IntelligenceError("intelligence version or exploitation profile is unsupported")
        _uri(advisory["vendor_reference"])
        _uri(advisory["exploitation_reference"])
        _date(advisory["reviewed_at"])
        _rights(advisory["rights"])
    _unique(advisory_ids)
    record_count += len(advisory_ids)
    withdrawals = []
    for withdrawal in _list(data["withdrawals"]):
        _keys(withdrawal, ("id", "reason", "reviewed_at", "references", "rights"))
        withdrawals.append(_identity(withdrawal["id"], 1024))
        _text(withdrawal["reason"])
        _date(withdrawal["reviewed_at"])
        _references(withdrawal["references"])
        _rights(withdrawal["rights"])
    _unique(withdrawals)
    if record_count > MAX_RECORDS:
        raise IntelligenceError("intelligence record count exceeds its bound")
    return data


def _time(value):
    try:
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
            raise ValueError()
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise IntelligenceError("intelligence timestamp is malformed") from exc


def utc_now():
    return datetime.now(timezone.utc)


def format_time(value):
    if value.tzinfo is None:
        raise IntelligenceError("intelligence time must include a timezone")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_manifest(payload: bytes, now: Optional[datetime] = None, *, allow_expired=False) -> Dict[str, Any]:
    data = strict_json(payload, MAX_MANIFEST_BYTES)
    _keys(data, ("schema_version", "feed_id", "sequence", "payload_sha256", "payload_size", "engine_capability", "issued_at", "expires_at"))
    if data["schema_version"] != SCHEMA_VERSION or data["feed_id"] != FEED_ID or data["engine_capability"] != ENGINE_CAPABILITY:
        raise IntelligenceError("intelligence manifest schema, feed, or engine capability is unsupported")
    if type(data["sequence"]) is not int or not 1 <= data["sequence"] <= 2 ** 53 - 1:
        raise IntelligenceError("intelligence sequence is outside its bound")
    if type(data["payload_size"]) is not int or not 0 < data["payload_size"] <= MAX_PAYLOAD_BYTES or not isinstance(data["payload_sha256"], str) or not _HEX.fullmatch(data["payload_sha256"]):
        raise IntelligenceError("intelligence payload binding is malformed")
    issued, expires = _time(data["issued_at"]), _time(data["expires_at"])
    current = now or utc_now()
    if not timedelta(0) < expires - issued <= timedelta(days=MAX_VALIDITY_DAYS):
        raise IntelligenceError("intelligence validity period is unsupported")
    if issued > current + MAX_CLOCK_SKEW:
        raise IntelligenceError("intelligence issue time is in the future")
    if not allow_expired and expires <= current:
        raise IntelligenceError("intelligence update has expired")
    return data


def build_manifest(payload: bytes, sequence: int, issued_at: datetime, validity_days: int = MAX_VALIDITY_DAYS) -> Dict[str, Any]:
    validate_payload(payload)
    if type(validity_days) is not int or not 1 <= validity_days <= MAX_VALIDITY_DAYS:
        raise IntelligenceError("intelligence validity period is unsupported")
    result = {"schema_version": SCHEMA_VERSION, "feed_id": FEED_ID, "sequence": sequence,
              "payload_sha256": hashlib.sha256(payload).hexdigest(), "payload_size": len(payload),
              "engine_capability": ENGINE_CAPABILITY, "issued_at": format_time(issued_at),
              "expires_at": format_time(issued_at + timedelta(days=validity_days))}
    return validate_manifest(canonical_json(result), now=issued_at)


def record_identities(data: Mapping[str, Any]) -> Dict[str, str]:
    """Identify changes that could remove an existing detection or claim."""
    records = {}

    def add(kind, parts, meaning):
        identity = kind + ":" + hashlib.sha256(canonical_json(parts)).hexdigest()
        if identity in records:
            raise IntelligenceError("intelligence contains duplicate detection identities")
        records[identity] = meaning

    for campaign in data["npm_campaigns"]:
        for package in campaign["packages"]:
            for version in package["versions"]:
                add("npm-package", [campaign["id"], package["name"], version], "exact")
            if package["broad_advisory"] == "all_versions":
                add("npm-advisory", [campaign["id"], package["name"]], "all_versions")
        for digest in campaign["payload_sha256"]:
            add("payload", [campaign["id"], digest], "sha256")
        for domain in campaign["malicious_domains"]:
            add("domain", [campaign["id"], domain], "domain")
    for advisory in data["vendor_advisories"]:
        claim = [advisory[key] for key in ("id", "package", "cve", "comparator", "fixed_floor")]
        add("vendor", claim, "vendor_advisory")
    return records


def validate_transition(previous: Mapping[str, Any], candidate: Mapping[str, Any]) -> None:
    before, after = record_identities(previous), record_identities(candidate)
    changed = {key for key, value in before.items() if after.get(key) != value}
    previous_reviews = {entry["id"]: entry for entry in previous["withdrawals"]}
    reviewed = {entry["id"]: entry for entry in candidate["withdrawals"]}
    if not set(previous_reviews) <= set(reviewed):
        raise IntelligenceError("intelligence correction history must be retained")
    if not changed <= set(reviewed):
        raise IntelligenceError("intelligence detection removal requires an explicit reviewed withdrawal")
    for identity in changed & set(previous_reviews):
        old, new = previous_reviews[identity], reviewed[identity]
        if (new["reviewed_at"] <= old["reviewed_at"]
                and " ".join(old["reason"].split()) == " ".join(new["reason"].split())
                and set(old["references"]) == set(new["references"])):
            raise IntelligenceError("intelligence detection removal requires a renewed reviewed withdrawal")


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class IntelligenceSnapshot:
    payload: Mapping[str, Any]
    digest: str
    source: str = "bundled"
    sequence: int = 0
    manifest_digest: str = ""
    status: str = "bundled"
    expires_at: str = ""
    coverage_error: str = ""
    activated_at: str = ""

    @property
    def identity(self) -> str:
        return hashlib.sha256(canonical_json([self.digest, self.source, self.sequence, self.manifest_digest, self.status])).hexdigest()

    @property
    def shortcut_eligible(self) -> bool:
        return self.status in ("bundled", "current") and not self.coverage_error

    @property
    def npm_campaigns(self):
        return self.payload["npm_campaigns"]

    @property
    def vendor_advisories(self):
        return self.payload["vendor_advisories"]

    def metadata(self) -> Dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "feed_id": FEED_ID, "source": self.source,
                "sequence": self.sequence, "digest": self.digest, "manifest_digest": self.manifest_digest,
                "identity": self.identity, "reviewed_at": self.payload["reviewed_at"],
                "status": self.status, "expires_at": self.expires_at, "coverage_error": self.coverage_error,
                "activated_at": self.activated_at}


def snapshot_from_payload(payload, **metadata) -> IntelligenceSnapshot:
    """Internal injection seam; public CLI has no alternate trust or state flags."""
    raw = payload if isinstance(payload, bytes) else canonical_json(payload)
    data = validate_payload(raw)
    return IntelligenceSnapshot(_freeze(data), hashlib.sha256(raw).hexdigest(), **metadata)


def bundled_snapshot() -> IntelligenceSnapshot:
    path = Path(__file__).resolve().parents[1] / "assets" / "runtime-intelligence.json"
    try:
        with path.open("rb") as stream:
            payload = stream.read(MAX_PAYLOAD_BYTES + 1)
        return snapshot_from_payload(payload)
    except (OSError, ValueError) as exc:
        raise IntelligenceError("bundled intelligence is unavailable or invalid") from exc


def load_intelligence_snapshot() -> IntelligenceSnapshot:
    from aurascan.core.intelligence_store import IntelligenceStore
    return IntelligenceStore().load()
