"""Offline capture admission and explicit review; no transport or sample execution."""

import copy
import hashlib
import json
import re
from datetime import datetime, timezone

try:
    from . import validate_security_data as contract
except ImportError:
    import validate_security_data as contract


CAPTURE_SCHEMA = "aurascan-security-capture/1.0"
BATCH_SCHEMA = "aurascan-security-intake/1.0"
REVIEW_SCHEMA = "aurascan-security-review/1.0"
REVIEW_REQUEST_SCHEMA = "aurascan-security-review-request/1.0"
ASSESSMENT_SCHEMA = "aurascan-security-assessment/1.0"
ASSESSMENT_REQUEST_SCHEMA = "aurascan-security-assessment-request/1.0"
MAX_CAPTURES = 32
MAX_FILES = 16
MAX_ITEMS = 256
SOURCE_TYPES = {"aurascan_fixture", "arch_git", "aur_metadata", "aur_git", "advisory"}
_PACKAGE = re.compile(r"[a-zA-Z0-9@][a-zA-Z0-9@._+\-]{0,127}\Z")
_PATH = re.compile(r"[a-zA-Z0-9_.+\-/]{1,256}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class IntakeError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check(condition, code):
    if not condition:
        raise IntakeError(code)


def _fields(value, fields):
    _check(isinstance(value, dict) and set(value) == set(fields), "fields")
    return value


def _hash(value):
    _check(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "digest")


def _time(value):
    _check(isinstance(value, str) and _UTC.fullmatch(value) is not None, "timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise IntakeError("timestamp") from None


def decode(payload):
    _check(isinstance(payload, bytes) and len(payload) <= 1024 * 1024, "metadata_bound")

    def pairs(values):
        result = {}
        for key, value in values:
            _check(key not in result, "duplicate_key")
            result[key] = value
        return result

    def number(_value):
        raise IntakeError("numeric_value")

    def integer(value):
        _check(len(value) <= 12, "numeric_value")
        return int(value)

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=number, parse_float=number, parse_int=integer)
    except (UnicodeError, ValueError, RecursionError):
        raise IntakeError("metadata_json") from None
    pending = [(value, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        _check(depth <= 32 and count <= 16384, "metadata_bound")
        if isinstance(current, dict):
            pending.extend((entry, depth + 1) for entry in current.values())
            pending.extend((entry, depth + 1) for entry in current.keys())
        elif isinstance(current, list):
            pending.extend((entry, depth + 1) for entry in current)
        elif isinstance(current, str):
            _check(len(current) <= 4096 and not any(0xD800 <= ord(c) <= 0xDFFF for c in current), "metadata_string")
    return value


def read_request(path):
    try:
        return decode(contract._read_manifest(path))
    except contract.ContractError:
        raise IntakeError("request_unreadable") from None


def _source_file(path):
    _check(isinstance(path, str) and _PATH.fullmatch(path) is not None, "source_path")
    _check(not path.startswith("/") and all(p not in {"", ".", "..", ".git"} for p in path.split("/")), "source_path")


def _capture_record(value):
    _fields(value, {"schema_version", "source_type", "source_uri", "package", "package_version",
                    "revision", "parent_revisions", "retrieved_at", "files", "coverage",
                    "transport_sha256", "content_sha256"})
    _check(value["schema_version"] == CAPTURE_SCHEMA, "capture_schema")
    _check(isinstance(value["source_type"], str) and value["source_type"] in SOURCE_TYPES, "source_type")
    try:
        contract._public_reference(value["source_uri"])
    except contract.ContractError:
        raise IntakeError("source_uri") from None
    for key in ("package", "package_version"):
        entry = value[key]
        if entry is not None:
            pattern = _PACKAGE if key == "package" else re.compile(r"[A-Za-z0-9._+:~\-]{1,128}\Z")
            _check(isinstance(entry, str) and pattern.fullmatch(entry) is not None, "package_identity")
    if value["source_type"] in {"arch_git", "aur_git", "aur_metadata", "aurascan_fixture"}:
        _check(value["package"] is not None, "package_identity")
    revision = value["revision"]
    _check(revision is None or (isinstance(revision, str) and contract._REVISION.fullmatch(revision)), "revision")
    if value["source_type"] in {"arch_git", "aur_git", "aurascan_fixture"}:
        _check(revision is not None, "revision")
    else:
        _check(revision is None and value["parent_revisions"] == [], "revision")
    parents = value["parent_revisions"]
    _check(isinstance(parents, list) and len(parents) <= 16, "parent_revisions")
    for parent in parents:
        _check(isinstance(parent, str) and contract._REVISION.fullmatch(parent) is not None, "parent_revisions")
    _check(len(set(parents)) == len(parents) and revision not in parents, "parent_revisions")
    _time(value["retrieved_at"])
    expected_coverage = {"advisory": "reference_only", "aur_metadata": "metadata_only"}.get(value["source_type"], "selected_files")
    _check(value["coverage"] == expected_coverage, "coverage")
    _check(isinstance(value["transport_sha256"], list) and len(value["transport_sha256"]) <= 32, "transport_bound")
    for sha in value["transport_sha256"]:
        _hash(sha)
    files = value["files"]
    _check(isinstance(files, list) and 1 <= len(files) <= MAX_FILES, "file_bound")
    seen = set()
    total = 0
    for entry in files:
        _fields(entry, {"path", "sha256", "size"})
        _source_file(entry["path"])
        _check(entry["path"] not in seen, "duplicate_file")
        seen.add(entry["path"])
        _hash(entry["sha256"])
        _check(type(entry["size"]) is int and 0 <= entry["size"] <= 256 * 1024, "file_bound")
        total += entry["size"]
    _check(total <= 1024 * 1024 and files == sorted(files, key=lambda e: e["path"]), "file_bound")
    _check(value["content_sha256"] == digest(canonical(files)), "content_identity")
    return value


def save_capture(store, capture):
    """Acquisition receipt only: no item labels or eligibility are produced."""
    files = []
    _check(isinstance(capture.files, dict) and 1 <= len(capture.files) <= MAX_FILES, "file_bound")
    total = 0
    for path in capture.files:
        _source_file(path)
    for path, payload in sorted(capture.files.items()):
        _check(isinstance(payload, bytes) and len(payload) <= 256 * 1024, "file_bound")
        total += len(payload)
        files.append({"path": path, "sha256": digest(payload), "size": len(payload)})
    _check(total <= 1024 * 1024, "file_bound")
    value = {key: getattr(capture, key) for key in ("source_type", "source_uri", "package", "package_version",
             "revision", "parent_revisions", "retrieved_at", "coverage", "transport_sha256")}
    value.update(schema_version=CAPTURE_SCHEMA, files=files, content_sha256=digest(canonical(files)))
    _capture_record(value)
    for payload in capture.files.values():
        store.put("blobs", payload)
    return store.put("captures", canonical(value))


def load_capture(store, capture_id):
    value = _capture_record(decode(store.get("captures", capture_id)))
    for entry in value["files"]:
        payload = store.get("blobs", entry["sha256"])
        _check(len(payload) == entry["size"], "capture_blob")
    return value


def _family(value):
    kind = value["source_type"]
    namespace = "aur" if kind in {"aur_metadata", "aur_git"} else kind
    key = value["package"] if value["package"] is not None else value["source_uri"]
    return "family-" + digest(canonical([namespace, key]))


def _candidate_id(value):
    # Retain separate revision nodes even when a later commit reverts to old
    # bytes. Collapsing those nodes turns a valid Git DAG into a parent cycle.
    # Blob/content hashes still deduplicate storage and connect split checks.
    return "item-" + digest(canonical([_family(value), value["revision"], value["content_sha256"]]))


def _expectations(store, capture):
    result = {"outcome": "not_specified", "action": "not_specified", "rule_ids": []}
    if capture["source_type"] != "aurascan_fixture":
        return result
    selected = next((entry for entry in capture["files"] if entry["path"] == "expected.json"), None)
    _check(selected is not None, "fixture_expectations")
    value = decode(store.get("blobs", selected["sha256"]))
    _check(isinstance(value, dict), "fixture_expectations")
    rules = value.get("expected_rule_ids")
    action = value.get("expected_action")
    _check(isinstance(rules, list) and len(rules) <= 64 and isinstance(action, str) and action in contract.ACTIONS, "fixture_expectations")
    _check(all(isinstance(rule, str) and contract._RULE_ID.fullmatch(rule) for rule in rules), "fixture_expectations")
    _check(len(set(rules)) == len(rules), "fixture_expectations")
    return {"outcome": "detected" if rules else "not_detected", "action": action, "rule_ids": sorted(rules)}


def _candidate(store, capture):
    fixture = capture["source_type"] == "aurascan_fixture"
    kind = "regression_fixture" if fixture else "advisory_incident" if capture["source_type"] == "advisory" else "package_observation"
    return {
        "id": _candidate_id(capture), "kinds": [kind], "origin": "synthetic" if fixture else "real",
        "collected_at": capture["retrieved_at"][:10],
        "sources": [{"kind": "public", "reference": capture["source_uri"],
                     "revision": capture["revision"], "sha256": capture["content_sha256"]}],
        "family_id": _family(capture), "parent_ids": [],
        "artifact": {"kind": "digest_only", "sha256": capture["content_sha256"]},
        "classification": "unknown", "claim_level": "none",
        "behavior": {"verified": [], "suspected": []}, "affected_versions": [],
        "expected": _expectations(store, capture), "observations": [],
        "review": {"status": "unreviewed", "basis_refs": []},
        "rights": {"analysis": "unknown", "training": "unknown", "commercial_training": "unknown",
                   "redistribution": "unknown", "basis_refs": [], "provider_training": "unknown", "provider_basis_refs": []},
        "provenance": {"status": "unknown", "basis_refs": [], "proprietary_provider_derived": "unknown"},
        "generation": {"method": "unknown", "model_refs": [], "basis_refs": []},
        "privacy": {"status": "unknown", "visibility": "public"}, "partition": "quarantine",
        "eligibility": {"training": False, "commercial_training": False, "evaluation": False, "redistribution": False},
    }


def _validate_candidates(document):
    _fields(document, {"schema_version", "items"})
    _check(document["schema_version"] == contract.SCHEMA_VERSION, "manifest_schema")
    _check(isinstance(document["items"], list) and len(document["items"]) <= MAX_ITEMS, "item_bound")
    records = []
    try:
        for position, item in enumerate(document["items"], 1):
            contract._validate_item(item)
            _check(item["partition"] == "quarantine" and not any(item["eligibility"].values()), "candidate_state")
            records.append((item, 1, position))
        contract._check_overlap(records)
    except contract.ContractError:
        raise IntakeError("candidate_contract") from None


def load_batch(store, batch_id):
    batch = decode(store.get("manifests", batch_id))
    _fields(batch, {"schema_version", "manifest_sha256", "capture_refs", "review_refs", "assessment_refs", "parent_batch", "created_at"})
    _check(batch["schema_version"] == BATCH_SCHEMA, "batch_schema")
    _hash(batch["manifest_sha256"])
    _time(batch["created_at"])
    if batch["parent_batch"] is not None:
        _hash(batch["parent_batch"])
    document = decode(store.get("manifests", batch["manifest_sha256"]))
    _validate_candidates(document)
    ids = {item["id"] for item in document["items"]}
    _check(isinstance(batch["capture_refs"], dict) and set(batch["capture_refs"]) == ids, "capture_refs")
    captures = []
    for item in document["items"]:
        refs = batch["capture_refs"][item["id"]]
        _check(isinstance(refs, list) and 1 <= len(refs) <= 16, "capture_refs")
        for ref in refs:
            _hash(ref)
        _check(len(set(refs)) == len(refs), "capture_refs")
        sources = []
        for ref in refs:
            captured = load_capture(store, ref)
            captures.append(captured)
            _check(_candidate_id(captured) == item["id"] and _family(captured) == item["family_id"]
                   and captured["content_sha256"] == item["artifact"]["sha256"], "capture_binding")
            expected = _candidate(store, captured)
            for field in ("kinds", "origin", "artifact", "expected"):
                _check(item[field] == expected[field], "capture_binding")
            if expected["sources"][0] not in sources:
                sources.append(expected["sources"][0])
        _check(sorted(item["sources"], key=canonical) == sorted(sources, key=canonical), "capture_binding")
    revisions, history, content_families = {}, {}, {}
    for captured in captures:
        family, content = _family(captured), captured["content_sha256"]
        _check(content not in content_families or content_families[content] == family, "lineage_collision")
        content_families[content] = family
        if captured["revision"] is not None:
            key = (family, captured["revision"])
            value = (content, sorted(captured["parent_revisions"]))
            _check(key not in history or history[key] == value, "upstream_history_changed")
            history[key], revisions[key] = value, _candidate_id(captured)
    for item in document["items"]:
        parents = set()
        for captured in captures:
            if _candidate_id(captured) == item["id"]:
                parents.update(revisions[(_family(captured), revision)] for revision in captured["parent_revisions"]
                               if (_family(captured), revision) in revisions)
        parents.discard(item["id"])
        _check(set(item["parent_ids"]) == parents, "capture_binding")
    reviews, assessments = {}, {}
    for field in ("review_refs", "assessment_refs"):
        _check(isinstance(batch[field], list) and len(batch[field]) <= 256, "evidence_bound")
        for ref in batch[field]:
            _hash(ref)
            evidence = decode(store.get("reviews", ref))
            if field == "review_refs":
                _fields(evidence, {"schema_version", "request", "base_batch", "reviewed_at"})
                _check(evidence["schema_version"] == REVIEW_SCHEMA, "review_schema")
                _time(evidence["reviewed_at"])
                request = evidence["request"]
                _review_request(request)
                original = _evidence_base(store, evidence["base_batch"], request["item_id"], request["candidate_sha256"], request["manifest_sha256"])
                historical = copy.deepcopy(original)
                historical["review"] = {"status": request["status"], "basis_refs": request["basis_refs"]}
                historical["classification"], historical["claim_level"] = request["classification"], request["claim_level"]
                historical["behavior"]["verified"] = request["verified_behaviors"]
                try:
                    contract._validate_item(historical)
                except contract.ContractError:
                    raise IntakeError("review_request") from None
                reviews[request["item_id"]] = (request, original)
            else:
                _fields(evidence, {"schema_version", "request", "base_batch", "item_id", "assessed_at"})
                _check(evidence["schema_version"] == ASSESSMENT_SCHEMA, "assessment_schema")
                _time(evidence["assessed_at"])
                request = evidence["request"]
                _assessment_request(request)
                _evidence_base(store, evidence["base_batch"], evidence["item_id"], request["candidate_sha256"])
                assessments["ref-" + ref] = (evidence["item_id"], request)
        _check(len(set(batch[field])) == len(batch[field]), "duplicate_evidence")
    for item in document["items"]:
        if item["review"]["status"] != "unreviewed":
            evidence = reviews.get(item["id"])
            _check(evidence is not None, "review_binding")
            request, original = evidence
            retained = set(item) - {"review", "classification", "claim_level", "behavior", "observations"}
            _check(all(item[key] == original[key] for key in retained), "review_binding")
            _check(item["review"] == {"status": request["status"], "basis_refs": request["basis_refs"]}
                   and item["classification"] == request["classification"] and item["claim_level"] == request["claim_level"]
                   and item["behavior"]["verified"] == request["verified_behaviors"], "review_binding")
        else:
            _check(item["classification"] == "unknown" and item["claim_level"] == "none"
                   and item["behavior"] == {"verified": [], "suspected": []}, "unreviewed_claim")
        for observation in item["observations"]:
            _check(observation["model_ref"] is None and len(observation["evidence_refs"]) == 1, "assessment_binding")
            evidence = assessments.get(observation["evidence_refs"][0])
            _check(evidence is not None and evidence[0] == item["id"]
                   and all(observation[key] == evidence[1][key] for key in ("outcome", "action", "rule_ids")), "assessment_binding")
    return batch, document


def _evidence_base(store, base, item_id, candidate_sha, manifest_sha=None):
    """Check the exact earlier statement, without recursive history traversal."""
    _hash(base)
    _hash(candidate_sha)
    batch = decode(store.get("manifests", base))
    _fields(batch, {"schema_version", "manifest_sha256", "capture_refs", "review_refs", "assessment_refs", "parent_batch", "created_at"})
    _check(batch["schema_version"] == BATCH_SCHEMA, "batch_schema")
    if manifest_sha is not None:
        _check(batch["manifest_sha256"] == manifest_sha, "evidence_binding")
    document = decode(store.get("manifests", batch["manifest_sha256"]))
    _validate_candidates(document)
    item = next((item for item in document["items"] if item["id"] == item_id), None)
    _check(item is not None and digest(canonical(item)) == candidate_sha, "evidence_binding")
    return item


def _publish_batch(store, document, refs, parent, review_refs, assessment_refs, now):
    _validate_candidates(document)
    _time(now)
    manifest_id = store.put("manifests", canonical(document))
    batch = {"schema_version": BATCH_SCHEMA, "manifest_sha256": manifest_id, "capture_refs": refs,
             "parent_batch": parent, "review_refs": review_refs, "assessment_refs": assessment_refs, "created_at": now}
    batch_id = store.put("manifests", canonical(batch))
    return {"batch_sha256": batch_id, "manifest_sha256": manifest_id, "items": len(document["items"])}


def intake(store, capture_ids, base=None, now=None):
    """Admit only explicit captured objects; this function cannot fetch."""
    _check(isinstance(capture_ids, list) and 1 <= len(capture_ids) <= MAX_CAPTURES, "capture_bound")
    if base is not None:
        _hash(base)
        batch, document = load_batch(store, base)
        document = copy.deepcopy(document)
        refs = copy.deepcopy(batch["capture_refs"])
        review_refs, assessments = batch["review_refs"][:], batch["assessment_refs"][:]
    else:
        document = {"schema_version": contract.SCHEMA_VERSION, "items": []}
        refs, review_refs, assessments = {}, [], []
    items = {item["id"]: item for item in document["items"]}
    previous = copy.deepcopy(items)
    all_captures = {}
    for values in refs.values():
        for ref in values:
            all_captures[ref] = load_capture(store, ref)
    for ref in capture_ids:
        _hash(ref)
        all_captures[ref] = load_capture(store, ref)
    content_families, revisions, history = {}, {}, {}
    for captured in all_captures.values():
        family, content = _family(captured), captured["content_sha256"]
        _check(content not in content_families or content_families[content] == family, "lineage_collision")
        content_families[content] = family
        if captured["revision"] is not None:
            key = (family, captured["revision"])
            _check(key not in revisions or revisions[key][0] == content, "upstream_revision_changed")
            parents = sorted(captured["parent_revisions"])
            _check(key not in history or history[key] == parents, "upstream_history_changed")
            history[key] = parents
            revisions[key] = (content, _candidate_id(captured))
    for ref in sorted(set(capture_ids)):
        captured = all_captures[ref]
        value = _candidate(store, captured)
        item_id = value["id"]
        if item_id not in items:
            _check(len(items) < MAX_ITEMS, "item_bound")
            items[item_id] = value
            refs[item_id] = []
        else:
            value = items[item_id]
            source = _candidate(store, captured)["sources"][0]
            if source not in value["sources"]:
                _check(len(value["sources"]) < 16, "source_bound")
                value["sources"].append(source)
        if ref not in refs[item_id]:
            _check(len(refs[item_id]) < 16, "capture_bound")
            refs[item_id].append(ref)
    # Git parents absent from the selected history remain explicit capture
    # metadata. Corpus parent IDs name only retained, actually linked items.
    for captured in all_captures.values():
        item = items[_candidate_id(captured)]
        for revision in captured["parent_revisions"]:
            parent = revisions.get((_family(captured), revision))
            if parent and parent[1] != item["id"] and parent[1] not in item["parent_ids"]:
                _check(len(item["parent_ids"]) < 16, "parent_bound")
                item["parent_ids"].append(parent[1])
    for item_id, item in items.items():
        if item_id in previous and item != previous[item_id]:
            # New source or retained ancestry changes the statement reviewed.
            # Its prior decision survives in the immutable parent batch only.
            item["review"] = {"status": "unreviewed", "basis_refs": []}
            item["classification"], item["claim_level"] = "unknown", "none"
            item["behavior"] = {"verified": [], "suspected": []}
    document["items"] = sorted(items.values(), key=lambda item: item["id"])
    return _publish_batch(store, document, refs, base, review_refs, assessments, now or utc_now())


def _review_request(request):
    _fields(request, {"schema_version", "item_id", "candidate_sha256", "manifest_sha256", "reviewer_ref",
                      "status", "basis_refs", "classification", "claim_level", "verified_behaviors"})
    _check(request["schema_version"] == REVIEW_REQUEST_SCHEMA, "review_schema")
    _check(isinstance(request["status"], str) and request["status"] in {"human_validated", "deterministic_validated", "independently_validated", "rejected"}, "review_status")
    _check(isinstance(request["reviewer_ref"], str) and contract._REF_ID.fullmatch(request["reviewer_ref"]), "reviewer_ref")
    _hash(request["candidate_sha256"])
    _hash(request["manifest_sha256"])
    try:
        contract._pattern(request["item_id"], contract._ITEM_ID)
        contract._symbols(request["basis_refs"], contract._REF_ID, 16, minimum=1)
        contract._symbols(request["verified_behaviors"], contract._LABEL, 32)
        contract._enum(request["classification"], {"unknown", "benign", "malicious", "suspicious"})
        contract._enum(request["claim_level"], {"none", "suspicious_behavior", "detector_bypass", "exploitability", "compromise"})
    except contract.ContractError:
        raise IntakeError("review_request") from None


def review(store, base, request, now=None):
    """Explicit operator declaration; validated review never enables data use."""
    _review_request(request)
    batch, document = load_batch(store, base)
    document = copy.deepcopy(document)
    _check(request["manifest_sha256"] == batch["manifest_sha256"], "stale_review")
    item = next((item for item in document["items"] if item["id"] == request["item_id"]), None)
    _check(item is not None and digest(canonical(item)) == request["candidate_sha256"], "stale_review")
    item["review"] = {"status": request["status"], "basis_refs": request["basis_refs"]}
    item["classification"], item["claim_level"] = request["classification"], request["claim_level"]
    item["behavior"]["verified"] = request["verified_behaviors"]
    _check(bool(request["basis_refs"]), "review_basis")
    _validate_candidates(document)
    receipt = {"schema_version": REVIEW_SCHEMA, "request": request, "base_batch": base, "reviewed_at": now or utc_now()}
    _time(receipt["reviewed_at"])
    review_id = store.put("reviews", canonical(receipt))
    _check(len(batch["review_refs"]) < 256, "evidence_bound")
    return _publish_batch(store, document, batch["capture_refs"], base, batch["review_refs"] + [review_id],
                          batch["assessment_refs"], receipt["reviewed_at"])


def _assessment_request(assessment):
    _fields(assessment, {"schema_version", "candidate_sha256", "tool_revision", "scanner_version", "scope",
                         "outcome", "action", "rule_ids"})
    _check(assessment["schema_version"] == ASSESSMENT_REQUEST_SCHEMA and assessment["scope"] == "deterministic_control_text", "assessment_schema")
    _check(isinstance(assessment["tool_revision"], str) and contract._REVISION.fullmatch(assessment["tool_revision"]), "assessment_revision")
    _check(isinstance(assessment["scanner_version"], str) and contract._APP_VERSION.fullmatch(assessment["scanner_version"]), "assessment_version")
    _hash(assessment["candidate_sha256"])
    result = {key: assessment[key] for key in ("outcome", "action", "rule_ids")}
    result.update(model_ref=None, evidence_refs=["ref-" + assessment["candidate_sha256"]])
    try:
        contract._result(result, observation=True)
    except contract.ContractError:
        raise IntakeError("assessment_result") from None


def attach_assessment(store, base, item_id, assessment, now=None):
    """Store a bounded explicit AuraScan assessment without changing labels."""
    _assessment_request(assessment)
    batch, document = load_batch(store, base)
    document = copy.deepcopy(document)
    item = next((item for item in document["items"] if item["id"] == item_id), None)
    _check(item is not None and digest(canonical(item)) == assessment["candidate_sha256"], "stale_assessment")
    timestamp = now or utc_now()
    _time(timestamp)
    receipt = {"schema_version": ASSESSMENT_SCHEMA, "request": assessment, "base_batch": base,
               "item_id": item_id, "assessed_at": timestamp}
    sha = digest(canonical(receipt))
    observation = {key: assessment[key] for key in ("outcome", "action", "rule_ids")}
    observation.update(model_ref=None, evidence_refs=["ref-" + sha])
    item["observations"].append(observation)
    _validate_candidates(document)
    store.put("reviews", canonical(receipt))
    _check(len(batch["assessment_refs"]) < 256, "evidence_bound")
    return _publish_batch(store, document, batch["capture_refs"], base, batch["review_refs"],
                          batch["assessment_refs"] + [sha], timestamp)
