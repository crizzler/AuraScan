"""Static catalog of prompt-injection classes, severities and default-enabled sets.

Mirrors ``Core/Injection/InjectionClassCatalog.cs``. This module is rule data inside the
``analysis`` layer, not the AuraScan ``catalog`` layer (``catalog_modules()`` matches module
names), so INV-010/INV-012 do not apply to it.

Spike scope (Card A): only ``instruction-override`` is ported here, so
``DEFAULT_ENABLED_CLASS_IDS`` is the one ported id. ``C_SHARP_DEFAULT_ENABLED_CLASS_IDS`` keeps the
original five default-on ids for reference so the parity gate can assert the difference.
"""

from typing import Tuple

INSTRUCTION_OVERRIDE = "instruction-override"
PERSONA_HIJACK = "persona-hijack"
TOOL_COMMAND = "tool-command"
DATA_EXFILTRATION = "data-exfiltration"
DELIMITER_ESCAPE = "delimiter-escape"
ENCODED_OBFUSCATED = "encoded-obfuscated"
MULTILINGUAL = "multilingual"

# Taxonomy order, exactly as the C# catalog enumerates it.
CLASS_IDS = (
    INSTRUCTION_OVERRIDE,
    PERSONA_HIJACK,
    TOOL_COMMAND,
    DATA_EXFILTRATION,
    DELIMITER_ESCAPE,
    ENCODED_OBFUSCATED,
    MULTILINGUAL,
)

# The C# default-on set (tool-command and delimiter-escape ship disabled there).
C_SHARP_DEFAULT_ENABLED_CLASS_IDS = (
    INSTRUCTION_OVERRIDE,
    PERSONA_HIJACK,
    DATA_EXFILTRATION,
    ENCODED_OBFUSCATED,
    MULTILINGUAL,
)

# Card A: the unported classes are not registered, so only this id is enabled.
DEFAULT_ENABLED_CLASS_IDS = (INSTRUCTION_OVERRIDE,)

_SEVERITY = {
    INSTRUCTION_OVERRIDE: "HIGH",
    PERSONA_HIJACK: "MEDIUM",
    TOOL_COMMAND: "HIGH",
    DATA_EXFILTRATION: "HIGH",
    DELIMITER_ESCAPE: "LOW",
    ENCODED_OBFUSCATED: "MEDIUM",
    MULTILINGUAL: "HIGH",
}

_DISPLAY = {
    INSTRUCTION_OVERRIDE: "Instruction override",
    PERSONA_HIJACK: "Persona hijack",
    TOOL_COMMAND: "Tool command",
    DATA_EXFILTRATION: "Data exfiltration",
    DELIMITER_ESCAPE: "Delimiter escape",
    ENCODED_OBFUSCATED: "Encoded / obfuscated",
    MULTILINGUAL: "Multilingual",
}


def normalize(class_id: str) -> str:
    """Canonical lowercase id, or the trimmed input when unknown (never None)."""
    if not class_id:
        return ""
    trimmed = class_id.strip()
    lowered = trimmed.lower()
    for known in CLASS_IDS:
        if known == lowered:
            return known
    return lowered


def is_known(class_id: str) -> bool:
    if not class_id:
        return False
    return class_id.strip().lower() in CLASS_IDS


def severity_of(class_id: str) -> str:
    """Static severity of a class; unknown ids are treated as ``LOW``."""
    return _SEVERITY.get(normalize(class_id), "LOW")


def display_name(class_id: str) -> str:
    normalized = normalize(class_id)
    if normalized in _DISPLAY:
        return _DISPLAY[normalized]
    return class_id or ""


def is_default_enabled(class_id: str) -> bool:
    return normalize(class_id) in DEFAULT_ENABLED_CLASS_IDS


def rule_id_for(detector_id: str) -> str:
    """``override.literal.x`` -> ``INJ-OVERRIDE-LITERAL-X``."""
    cleaned = "".join(ch if (ch.isalnum() or ch in "._-") else "-" for ch in (detector_id or ""))
    cleaned = cleaned.replace(".", "-").replace("_", "-").upper()
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return "INJ-" + cleaned.strip("-")


def as_tuple(values) -> Tuple[str, ...]:
    return tuple(values)
