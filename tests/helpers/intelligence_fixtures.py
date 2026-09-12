"""Validated inert runtime-intelligence snapshots for scanner regressions."""

import hashlib
import json
from pathlib import Path

from aurascan.core.intelligence import snapshot_from_payload


def bundled_payload():
    path = Path(__file__).resolve().parents[2] / "aurascan/assets/runtime-intelligence.json"
    return json.loads(path.read_text(encoding="utf-8"))


def inert_signature_snapshot(payload):
    data = bundled_payload()
    data["npm_campaigns"][0]["payload_sha256"] = [hashlib.sha256(payload).hexdigest()]
    return snapshot_from_payload(data)


def inert_domain_snapshot():
    data = bundled_payload()
    data["npm_campaigns"][0]["malicious_domains"] = ["c2.example.invalid"]
    return snapshot_from_payload(data)
