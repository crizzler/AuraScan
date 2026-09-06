"""Inspect precompiled Python carrier names and headers as inert bytes only.

No code object is unmarshaled, imported, executed, or disassembled.  A known
header establishes only its declared invalidation mode; it cannot establish
that the remaining bytes are executable or correspond to any nearby source.
"""

from typing import List

from aurascan.core.models import (
    Confidence, EvidenceQuality, Finding, Phase, Severity, Source,
)


PYTHON_PRECOMPILED_SUFFIXES = (".pyc", ".pyo", ".pyd")
PYTHON_BYTECODE = "python-bytecode"
PYTHON_UNCHECKED_HASH = "python-bytecode-unchecked-hash"
PYTHON_PRECOMPILED_CANDIDATE = "python-precompiled-candidate"
PYTHON_PRECOMPILED_KINDS = frozenset({
    PYTHON_BYTECODE, PYTHON_UNCHECKED_HASH, PYTHON_PRECOMPILED_CANDIDATE,
})

# Released CPython 3.7 through 3.14 magic values, independently of the Python
# running AuraScan.  Unknown versions still receive name-based presence review;
# their flags are never guessed.  Source: CPython's pycore_magic_number.h and
# https://peps.python.org/pep-0552/ (the latter defines the 16-byte header).
_PEP552_MAGIC_NUMBERS = frozenset({
    3394, 3413, 3425, 3439, 3495, 3531, 3571, 3627,
})
_LEGACY_MAGIC_HEADER_LENGTHS = {
    62211: 8,  # CPython 2.7
    3131: 8, 3151: 8, 3180: 8,  # CPython 3.0 through 3.2
    3230: 12, 3310: 12, 3350: 12, 3351: 12, 3379: 12,
}


def is_python_precompiled_path(path: str) -> bool:
    return str(path).lower().endswith(PYTHON_PRECOMPILED_SUFFIXES)


def classify_python_precompiled(path: str, prefix: bytes) -> str:
    """Return a fixed carrier label after examining at most 16 header bytes.

    Names select review candidates, including native-extension ``.pyd`` files;
    they do not prove Python bytecode.  Only complete, recognized CPython
    headers receive a bytecode label or PEP 552 invalidation interpretation.
    Timestamp words in pre-3.7 headers are never mistaken for PEP 552 flags.
    """

    header = prefix[:16]
    if len(header) >= 4 and header[2:4] == b"\r\n":
        magic = int.from_bytes(header[:2], "little")
        if magic in _PEP552_MAGIC_NUMBERS and len(header) == 16:
            flags = int.from_bytes(header[4:8], "little")
            if flags == 1:
                return PYTHON_UNCHECKED_HASH
            if flags in {0, 2, 3}:
                return PYTHON_BYTECODE
        minimum = _LEGACY_MAGIC_HEADER_LENGTHS.get(magic)
        if minimum is not None and len(header) >= minimum:
            return PYTHON_BYTECODE
    return PYTHON_PRECOMPILED_CANDIDATE if is_python_precompiled_path(path) else ""


def python_precompiled_findings(
    kind: str,
    file_path: str,
    phase: Phase,
    *,
    pkg_name: str = "unknown",
    pkg_ver: str = "unknown",
    file_hash: str = "",
    include_presence: bool = True,
) -> List[Finding]:
    """Build bounded explanations from fixed metadata, never carrier content."""

    if kind not in PYTHON_PRECOMPILED_KINDS:
        return []
    findings: List[Finding] = []
    if include_presence:
        findings.append(Finding(
            rule_id="PYTHON-BYTECODE-PRESENT-001",
            package_name=pkg_name,
            package_version=pkg_ver,
            phase=phase,
            source=Source.deterministic_rule,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence_quality=EvidenceQuality.strong_heuristic,
            file_path=file_path,
            explanation=(
                "A precompiled Python carrier candidate is present in inspected package "
                "inputs. Nearby Python source does not establish the behavior of these bytes."
            ),
            recommendation=(
                "Review the carrier's provenance and expected build or import role "
                "before accepting the package."
            ),
            false_positive_notes=(
                "Precompiled files can be legitimate. A filename or header does not prove "
                "valid executable content, malicious behavior, repository tracking, or execution."
            ),
            blocks_installation=False,
            requires_manual_review=True,
            evidence_snippet="precompiled Python carrier candidate is present in inspected inputs",
            file_hash=file_hash,
        ))
    if kind == PYTHON_UNCHECKED_HASH:
        findings.append(Finding(
            rule_id="PYTHON-BYTECODE-UNCHECKED-HASH-001",
            package_name=pkg_name,
            package_version=pkg_ver,
            phase=phase,
            source=Source.deterministic_rule,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence_quality=EvidenceQuality.confirmed_static_pattern,
            file_path=file_path,
            explanation=(
                "A recognized CPython PEP 552 header declares hash-based bytecode with "
                "source checking disabled. Under the default interpreter policy, "
                "this mode does not validate the bytecode against nearby source."
            ),
            recommendation=(
                "Independently establish the precompiled artifact's provenance and "
                "intended use before building or installing."
            ),
            false_positive_notes=(
                "Unchecked hashes support legitimate reproducible distribution workflows. "
                "Only the header was interpreted; this finding does not prove a valid "
                "code object, source mismatch, malicious behavior, or execution."
            ),
            blocks_installation=False,
            requires_manual_review=True,
            evidence_snippet="recognized PEP 552 header declares unchecked hash invalidation",
            file_hash=file_hash,
        ))
    return findings
