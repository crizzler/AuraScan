#!/usr/bin/env python3
"""Validate explicitly supplied security-corpus metadata; never open samples.

This developer-only contract has no AuraScan runtime imports, network clients,
provider calls, directory discovery, or executable record fields. Validation is
limited to the supplied manifests and cannot establish legal permission, label
truth, privacy clearance, or absence of unknown training contamination.
"""

import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit


SCHEMA_VERSION = "aurascan-security-data/1.0"
MAX_MANIFESTS = 32
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_TOTAL_ITEMS = 4096
MAX_JSON_DEPTH = 48
MAX_JSON_NODES = 65536
MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 64

KINDS = frozenset({
    "public_benign", "historical_malicious", "advisory_incident",
    "synthetic_adversarial", "detector_bypass", "false_positive",
    "remediation_fix", "model_disagreement", "regression_fixture",
    "private_held_out", "package_observation",
})
PARTITIONS = frozenset({"quarantine", "training", "evaluation", "private_held_out"})
VALIDATED_REVIEWS = frozenset({"human_validated", "deterministic_validated", "independently_validated"})
OUTCOMES = frozenset({"detected", "not_detected", "incomplete", "not_run"})
ACTIONS = frozenset({"allow", "warn", "manual_review", "block", "not_specified"})
USES = frozenset({"training", "commercial_training", "evaluation", "redistribution"})
RIGHTS = frozenset({"analysis", "redistribution", "training", "commercial_training"})
_ITEM_FIELDS = frozenset({
    "id", "kinds", "origin", "collected_at", "sources", "family_id",
    "parent_ids", "artifact", "classification", "claim_level", "behavior",
    "affected_versions", "expected", "observations", "review", "rights",
    "privacy", "partition", "eligibility", "provenance", "generation",
})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_ITEM_ID = re.compile(r"item-[0-9a-f]{12,64}\Z")
_FAMILY_ID = re.compile(r"family-[0-9a-f]{12,64}\Z")
_REF_ID = re.compile(r"ref-[0-9a-f]{12,64}\Z")
_MODEL_ID = re.compile(r"model-[0-9a-f]{12,64}\Z")
_LABEL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_RULE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,95}\Z")
_APP_VERSION = re.compile(r"[0-9][A-Za-z0-9.+~:-]{0,63}\Z")
_PUBLIC_HOST = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\Z")


class ContractError(ValueError):
    """Only fixed codes and one-based record positions leave the validator."""

    def __init__(self, code: str, manifest: int = 0, item: int = 0):
        self.code = code
        self.manifest = manifest
        self.item = item
        super().__init__(code)


@dataclass(frozen=True)
class ValidationSummary:
    manifests: int
    items: int
    training: int
    evaluation: int
    private_held_out: int
    quarantined: int
    commercial_training: int
    redistribution: int


def _fail(code: str) -> None:
    raise ContractError(code)


def _fields(value: Any, fields: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        _fail("fields")
    return value


def _enum(value: Any, choices: Sequence[str]) -> None:
    if not isinstance(value, str) or value not in choices:
        _fail("enum")


def _pattern(value: Any, pattern: Any) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail("format")


def _list(value: Any, maximum: int, *, minimum: int = 0) -> List[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _fail("list_bound")
    return value


def _symbols(value: Any, pattern: Any, maximum: int, *, minimum: int = 0) -> None:
    values = _list(value, maximum, minimum=minimum)
    for element in values:
        _pattern(element, pattern)
    if len(set(values)) != len(values):
        _fail("duplicate_value")


def _public_reference(value: Any) -> None:
    if not isinstance(value, str) or len(value) > 2048 or "\\" in value:
        _fail("source_reference")
    if any(ord(character) < 33 or ord(character) > 126 for character in value):
        _fail("source_reference")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "https" and parsed.hostname is not None
            and _PUBLIC_HOST.fullmatch(parsed.hostname) is not None
            and parsed.username is None and parsed.password is None
            and parsed.port in {None, 443} and not parsed.query and not parsed.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        _fail("source_reference")


def _result(value: Any, *, observation: bool) -> None:
    keys = {"outcome", "action", "rule_ids"}
    if observation:
        keys.update({"model_ref", "evidence_refs"})
    result = _fields(value, keys)
    _enum(result["outcome"], OUTCOMES if observation else OUTCOMES | {"not_specified"})
    _enum(result["action"], ACTIONS)
    _symbols(result["rule_ids"], _RULE_ID, 64)
    if result["outcome"] in {"not_detected", "not_run", "not_specified"} and result["rule_ids"]:
        _fail("outcome_rules")
    if result["outcome"] == "not_run" and result["action"] != "not_specified":
        _fail("not_run_action")
    if observation:
        if result["model_ref"] is not None:
            _pattern(result["model_ref"], _MODEL_ID)
        _symbols(result["evidence_refs"], _REF_ID, 16)
        if result["outcome"] != "not_run" and not result["evidence_refs"]:
            _fail("observation_evidence")
        if result["outcome"] == "detected" and not result["rule_ids"] and result["model_ref"] is None:
            _fail("observation_detector")


def _validate_item(value: Any) -> Dict[str, Any]:
    item = _fields(value, _ITEM_FIELDS)
    _pattern(item["id"], _ITEM_ID)
    _pattern(item["family_id"], _FAMILY_ID)
    _symbols(item["parent_ids"], _ITEM_ID, 16)
    if item["id"] in item["parent_ids"]:
        _fail("lineage_cycle")
    kinds = _list(item["kinds"], len(KINDS), minimum=1)
    for kind in kinds:
        _enum(kind, KINDS)
    if len(set(kinds)) != len(kinds):
        _fail("duplicate_value")
    _enum(item["origin"], {"real", "synthetic", "mutated", "inferred"})
    if item["origin"] == "mutated" and not item["parent_ids"]:
        _fail("mutation_parent")
    provenance = _fields(item["provenance"], {"status", "basis_refs", "proprietary_provider_derived"})
    _enum(provenance["status"], {"reviewed", "unknown"})
    _enum(provenance["proprietary_provider_derived"], {"yes", "no", "unknown"})
    _symbols(provenance["basis_refs"], _REF_ID, 16)
    if provenance["status"] == "reviewed" and not provenance["basis_refs"]:
        _fail("provenance_basis")
    generation = _fields(item["generation"], {"method", "model_refs", "basis_refs"})
    _enum(generation["method"], {"none", "human", "tool", "model", "mixed", "unknown"})
    _symbols(generation["model_refs"], _MODEL_ID, 16)
    _symbols(generation["basis_refs"], _REF_ID, 16)
    if generation["method"] in {"model", "mixed"} and not generation["model_refs"]:
        _fail("generation_model")
    if generation["method"] in {"none", "human", "tool"} and generation["model_refs"]:
        _fail("generation_method")
    if generation["method"] not in {"none", "unknown"} and not generation["basis_refs"]:
        _fail("generation_basis")
    if item["origin"] != "real" and generation["method"] == "none":
        _fail("generation_origin")
    try:
        if not isinstance(item["collected_at"], str) or len(item["collected_at"]) != 10:
            _fail("collection_date")
        if date.fromisoformat(item["collected_at"]).isoformat() != item["collected_at"]:
            _fail("collection_date")
    except ValueError:
        _fail("collection_date")

    bound_source = False
    for source in _list(item["sources"], 16, minimum=1):
        source = _fields(source, {"kind", "reference", "revision", "sha256"})
        _enum(source["kind"], {"public", "private", "generated"})
        if source["kind"] == "public":
            _public_reference(source["reference"])
        else:
            _pattern(source["reference"], _REF_ID)
        if source["revision"] is not None:
            _pattern(source["revision"], _REVISION)
            bound_source = True
        if source["sha256"] is not None:
            _pattern(source["sha256"], _SHA256)
            bound_source = True

    artifact = _fields(item["artifact"], {"kind", "sha256"})
    _enum(artifact["kind"], {"metadata_only", "digest_only", "inert_fixture"})
    if artifact["kind"] == "metadata_only":
        if artifact["sha256"] is not None:
            _fail("metadata_only_digest")
    else:
        _pattern(artifact["sha256"], _SHA256)
    _enum(item["classification"], {"benign", "malicious", "suspicious", "unknown"})
    _enum(item["claim_level"], {"none", "suspicious_behavior", "detector_bypass", "exploitability", "compromise"})
    behavior = _fields(item["behavior"], {"verified", "suspected"})
    _symbols(behavior["verified"], _LABEL, 32)
    _symbols(behavior["suspected"], _LABEL, 32)
    if set(behavior["verified"]) & set(behavior["suspected"]):
        _fail("behavior_status_overlap")
    _symbols(item["affected_versions"], _APP_VERSION, 32)
    _result(item["expected"], observation=False)
    for observation in _list(item["observations"], 32):
        _result(observation, observation=True)

    review = _fields(item["review"], {"status", "basis_refs"})
    _enum(review["status"], VALIDATED_REVIEWS | {"unreviewed", "rejected"})
    _symbols(review["basis_refs"], _REF_ID, 16)
    if review["status"] != "unreviewed" and not review["basis_refs"]:
        _fail("review_basis")
    if behavior["verified"] and review["status"] not in VALIDATED_REVIEWS:
        _fail("unvalidated_behavior")
    if item["claim_level"] in {"detector_bypass", "exploitability", "compromise"}:
        if review["status"] not in VALIDATED_REVIEWS:
            _fail("unvalidated_claim")
    if item["claim_level"] in {"exploitability", "compromise"}:
        if review["status"] == "deterministic_validated":
            _fail("static_claim_escalation")

    rights = _fields(item["rights"], RIGHTS | {"basis_refs", "provider_training", "provider_basis_refs"})
    for purpose in RIGHTS:
        _enum(rights[purpose], {"allowed", "denied", "unknown"})
    _symbols(rights["basis_refs"], _REF_ID, 16)
    if any(rights[purpose] == "allowed" for purpose in RIGHTS) and not rights["basis_refs"]:
        _fail("rights_basis")
    _enum(rights["provider_training"], {"allowed", "denied", "unknown", "not_applicable"})
    _symbols(rights["provider_basis_refs"], _REF_ID, 16)
    if rights["provider_training"] == "allowed" and not rights["provider_basis_refs"]:
        _fail("provider_rights_basis")
    if rights["provider_training"] == "not_applicable" and provenance["proprietary_provider_derived"] != "no":
        _fail("provider_rights_applicability")
    privacy = _fields(item["privacy"], {"status", "visibility"})
    _enum(privacy["status"], {"clear", "sensitive", "unknown"})
    _enum(privacy["visibility"], {"public", "private"})
    _enum(item["partition"], PARTITIONS)
    eligibility = _fields(item["eligibility"], USES)
    if any(type(flag) is not bool for flag in eligibility.values()):
        _fail("eligibility_type")
    if eligibility["training"] and eligibility["evaluation"]:
        _fail("eligibility_overlap")
    if eligibility["commercial_training"] and not eligibility["training"]:
        _fail("commercial_training_requires_training")
    if item["partition"] == "quarantine" and any(eligibility.values()):
        _fail("quarantine_eligible")
    if eligibility["training"] and item["partition"] != "training":
        _fail("training_partition")
    if eligibility["evaluation"] and item["partition"] not in {"evaluation", "private_held_out"}:
        _fail("evaluation_partition")
    if item["partition"] == "private_held_out":
        if privacy["visibility"] != "private" or "private_held_out" not in kinds:
            _fail("heldout_visibility")
    elif "private_held_out" in kinds:
        _fail("heldout_partition")
    if any(eligibility.values()):
        if review["status"] not in VALIDATED_REVIEWS:
            _fail("eligibility_review")
        if privacy["status"] != "clear":
            _fail("eligibility_privacy")
        if rights["analysis"] != "allowed":
            _fail("eligibility_rights")
        if provenance["status"] != "reviewed" or generation["method"] == "unknown":
            _fail("eligibility_provenance")
        if eligibility["training"] and rights["training"] != "allowed":
            _fail("training_rights")
        if eligibility["commercial_training"] and rights["commercial_training"] != "allowed":
            _fail("commercial_training_rights")
        if eligibility["redistribution"] and rights["redistribution"] != "allowed":
            _fail("redistribution_rights")
        if eligibility["training"] or eligibility["redistribution"]:
            if provenance["proprietary_provider_derived"] == "unknown":
                _fail("eligibility_provider_provenance")
        if eligibility["training"]:
            if (rights["provider_training"] == "denied" or
                    (provenance["proprietary_provider_derived"] == "yes"
                     and rights["provider_training"] != "allowed")):
                _fail("provider_training_rights")
        if artifact["sha256"] is None and not bound_source:
            _fail("eligibility_identity")
    return item


def _restricted_uses(item: Dict[str, Any]) -> set:
    """Restrictions inherited through actual parents, not a model's assertion."""
    rights, provenance = item["rights"], item["provenance"]
    if (rights["analysis"] != "allowed" or provenance["status"] != "reviewed"
            or item["generation"]["method"] == "unknown"):
        return set(USES)
    restricted = {purpose for purpose in RIGHTS - {"analysis"} if rights[purpose] != "allowed"}
    provider = provenance["proprietary_provider_derived"]
    if provider == "unknown":
        restricted.update({"training", "redistribution"})
    if rights["provider_training"] == "denied" or (provider == "yes" and rights["provider_training"] != "allowed"):
        restricted.add("training")
    if "training" in restricted:
        restricted.add("commercial_training")
    return restricted


def _check_overlap(records: Sequence[Tuple[Dict[str, Any], int, int]]) -> None:
    by_id = {}  # type: Dict[str, int]
    for index, (item, manifest, position) in enumerate(records):
        if item["id"] in by_id:
            raise ContractError("duplicate_id", manifest, position)
        by_id[item["id"]] = index
    roots = list(range(len(records)))
    ranks = [0] * len(records)

    def root(index: int) -> int:
        while roots[index] != index:
            roots[index] = roots[roots[index]]
            index = roots[index]
        return index

    def join(left: int, right: int) -> None:
        left, right = root(left), root(right)
        if left == right:
            return
        if ranks[left] < ranks[right]:
            left, right = right, left
        roots[right] = left
        if ranks[left] == ranks[right]:
            ranks[left] += 1

    families = {}  # type: Dict[str, int]
    artifacts = {}  # type: Dict[str, int]
    source_revisions = {}  # type: Dict[Tuple[str, str], int]
    unknown_parents = {}  # type: Dict[str, int]
    unresolved = set()
    children = [[] for _record in records]
    pending_parents = [0] * len(records)
    restricted = [_restricted_uses(item) for item, _manifest, _position in records]
    for index, (item, manifest, position) in enumerate(records):
        for key, seen in ((item["family_id"], families), (item["artifact"]["sha256"], artifacts)):
            if key is not None:
                if key in seen:
                    join(index, seen[key])
                else:
                    seen[key] = index
        if item["artifact"]["kind"] == "metadata_only":
            for source in item["sources"]:
                if source["sha256"] is not None:
                    digest = source["sha256"]
                    if digest in artifacts:
                        join(index, artifacts[digest])
                    else:
                        artifacts[digest] = index
                if source["revision"] is not None:
                    reference = source["reference"]
                    if source["kind"] == "public":
                        parsed = urlsplit(reference)
                        reference = "https://" + parsed.hostname.lower() + (parsed.path or "/")
                    key = (reference, source["revision"])
                    if key in source_revisions:
                        join(index, source_revisions[key])
                    else:
                        source_revisions[key] = index
        for parent_id in item["parent_ids"]:
            parent_index = by_id.get(parent_id)
            if parent_index is None:
                if item["partition"] != "quarantine":
                    raise ContractError("unknown_parent", manifest, position)
                # Even absent ancestors are opaque lineage identities. Two
                # quarantined records naming one absent parent connect their
                # descendants; omission cannot sever a contamination bridge.
                if parent_id in unknown_parents:
                    join(index, unknown_parents[parent_id])
                else:
                    unknown_parents[parent_id] = index
                unresolved.add(index)
                continue
            join(index, parent_index)
            children[parent_index].append(index)
            pending_parents[index] += 1
    # Kahn's algorithm avoids recursion on a long attacker-controlled lineage.
    ready = [index for index, count in enumerate(pending_parents) if count == 0]
    completed = 0
    while ready:
        index = ready.pop()
        completed += 1
        for child in children[index]:
            restricted[child].update(restricted[index])
            pending_parents[child] -= 1
            if pending_parents[child] == 0:
                ready.append(child)
    if completed != len(records):
        index = next(index for index, count in enumerate(pending_parents) if count)
        raise ContractError("lineage_cycle", records[index][1], records[index][2])

    groups = {}  # type: Dict[int, List[int]]
    for index in range(len(records)):
        groups.setdefault(root(index), []).append(index)
    for indexes in groups.values():
        partitions = {records[index][0]["partition"] for index in indexes}
        if "training" in partitions and partitions & {"evaluation", "private_held_out"}:
            item, manifest, position = records[indexes[0]]
            raise ContractError("partition_overlap", manifest, position)
        if any(index in unresolved for index in indexes) and any(
            any(records[index][0]["eligibility"].values()) for index in indexes
        ):
            item, manifest, position = records[indexes[0]]
            raise ContractError("unresolved_lineage", manifest, position)
        if "private_held_out" in partitions and any(
            records[index][0]["privacy"]["visibility"] == "public"
            for index in indexes
        ):
            item, manifest, position = records[indexes[0]]
            raise ContractError("heldout_public_lineage", manifest, position)
        if "private_held_out" in partitions and any(
            records[index][0]["eligibility"]["redistribution"] for index in indexes
        ):
            raise ContractError("heldout_redistribution", records[indexes[0]][1], records[indexes[0]][2])

    for index, (item, manifest, position) in enumerate(records):
        if any(item["eligibility"][purpose] for purpose in restricted[index]):
            raise ContractError("lineage_rights", manifest, position)


def _decode(payload: bytes) -> Dict[str, Any]:
    if len(payload) > MAX_MANIFEST_BYTES:
        _fail("manifest_size")
    # Bound nesting before allocating decoded containers. JSON parsing still
    # performs the grammar checks; this scan only limits structural work.
    depth = 0
    quoted = False
    escaped = False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail("json_depth")
        elif byte in (125, 93):
            depth -= 1

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail("json_duplicate_key")
            result[key] = value
        return result

    def reject_constant(_value):
        _fail("json_constant")

    def reject_number(_value):
        _fail("json_number")

    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=reject_constant, parse_int=reject_number,
                          parse_float=reject_number)
    except ContractError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("json_invalid") from None
    pending = [data]
    count = 0
    while pending:
        value = pending.pop()
        count += 1
        if count > MAX_JSON_NODES:
            _fail("json_nodes")
        if isinstance(value, dict):
            pending.extend(value.values())
            pending.extend(value)
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            if len(value) > 2048 or any(ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF for character in value):
                _fail("json_string")
    return data


def _identity(info: Any) -> Tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_manifest(path: Any) -> bytes:
    descriptors = []
    directory_links = []
    try:
        path_text = os.fspath(path)
        if not isinstance(path_text, str) or not path_text or len(path_text.encode("utf-8")) > MAX_PATH_BYTES:
            _fail("manifest_path")
        if any(ord(character) < 32 or ord(character) == 127 for character in path_text):
            _fail("manifest_path")
        selected = Path(path_text)
        if ".." in selected.parts:
            _fail("manifest_path")
        if not selected.is_absolute():
            selected = Path.cwd() / selected
        parts = selected.parts[1:]
        if not parts or len(parts) > MAX_PATH_COMPONENTS:
            _fail("manifest_path")
        if not all(getattr(os, option, 0) for option in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
            _fail("no_follow_unavailable")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
        parent = os.open("/", flags)
        descriptors.append(parent)
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            directory_links.append((parent, part, info.st_dev, info.st_ino))
            parent = child
        target = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent)
        descriptors.append(target)
        before = os.fstat(target)
        if not stat.S_ISREG(before.st_mode):
            _fail("manifest_not_regular")
        if before.st_size < 0 or before.st_size > MAX_MANIFEST_BYTES:
            _fail("manifest_size")
        payload = bytearray()
        while len(payload) <= MAX_MANIFEST_BYTES:
            chunk = os.read(target, min(65536, MAX_MANIFEST_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_MANIFEST_BYTES:
            _fail("manifest_size")
        after = os.fstat(target)
        named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if len(payload) != before.st_size or _identity(before) != _identity(after) or _identity(after) != _identity(named):
            _fail("manifest_changed")
        for directory, component, device, inode in directory_links:
            named = os.stat(component, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino) != (device, inode):
                _fail("manifest_changed")
        return bytes(payload)
    except ContractError:
        raise
    except (OSError, TypeError, ValueError, UnicodeError):
        raise ContractError("manifest_unsafe_or_unreadable") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def validate_manifests(paths: Sequence[Any]) -> ValidationSummary:
    """Validate one explicit batch; no referenced content is accessed."""
    if not 1 <= len(paths) <= MAX_MANIFESTS:
        _fail("manifest_count")
    records = []
    total_bytes = 0
    for manifest, path in enumerate(paths, 1):
        try:
            payload = _read_manifest(path)
            total_bytes += len(payload)
            if total_bytes > MAX_TOTAL_BYTES:
                _fail("total_bytes")
            document = _fields(_decode(payload), {"schema_version", "items"})
            if document["schema_version"] != SCHEMA_VERSION:
                _fail("schema_version")
            items = _list(document["items"], MAX_TOTAL_ITEMS)
            if len(records) + len(items) > MAX_TOTAL_ITEMS:
                _fail("total_items")
        except ContractError as error:
            raise ContractError(error.code, manifest) from None
        for position, value in enumerate(items, 1):
            try:
                item = _validate_item(value)
            except ContractError as error:
                raise ContractError(error.code, manifest, position) from None
            records.append((item, manifest, position))
    _check_overlap(records)
    return ValidationSummary(
        manifests=len(paths), items=len(records),
        training=sum(item["eligibility"]["training"] for item, _manifest, _position in records),
        evaluation=sum(item["eligibility"]["evaluation"] for item, _manifest, _position in records),
        private_held_out=sum(item["partition"] == "private_held_out" for item, _manifest, _position in records),
        quarantined=sum(item["partition"] == "quarantine" for item, _manifest, _position in records),
        commercial_training=sum(item["eligibility"]["commercial_training"] for item, _manifest, _position in records),
        redistribution=sum(item["eligibility"]["redistribution"] for item, _manifest, _position in records),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--help"]:
        print("Usage: python tools/validate_security_data.py [--] MANIFEST.json [MANIFEST.json ...]")
        print("Offline metadata validation only; referenced artifacts and URLs are never opened.")
        return 0
    terminated = bool(arguments and arguments[0] == "--")
    if terminated:
        arguments = arguments[1:]
    try:
        if not terminated and any(argument.startswith("-") for argument in arguments):
            _fail("cli_arguments")
        summary = validate_manifests(arguments)
    except ContractError as error:
        print("ERROR manifest={} item={} code={}".format(
            error.manifest, error.item, error.code), file=sys.stderr)
        return 1
    print("PASS manifests={} items={} training_eligible={} evaluation_eligible={} "
          "private_held_out={} quarantined={} commercial_training_eligible={} "
          "redistribution_eligible={} scope=provided-manifests-only".format(
              summary.manifests, summary.items, summary.training, summary.evaluation,
              summary.private_held_out, summary.quarantined, summary.commercial_training,
              summary.redistribution))
    return 0


if __name__ == "__main__":
    sys.exit(main())
