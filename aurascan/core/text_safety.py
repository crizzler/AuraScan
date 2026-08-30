"""Display-boundary sanitizers for untrusted and model-authored text."""

import json
import re
import unicodedata
from typing import Any, Dict, Sequence, Tuple


_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\][^\x07]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~])"
)
_MULTISPACE = re.compile(r"[ \t\r\n]+")
_RESERVED_PRODUCT_PREFIX = re.compile(r"\[\s*aurascan\s*\]", re.IGNORECASE)
_TERMINAL_IMPERSONATION = re.compile(
    r"(?:^|[\r\n])\s*(?:\[(?:ok|safe|warning|error|critical)\]|(?:root|admin)@[^\s:]+[:#])",
    re.IGNORECASE,
)
_URL = re.compile(r"\b(?:[a-z][a-z0-9+.-]*://|www\.)\S+", re.IGNORECASE)
_BARE_NETWORK_DESTINATION = re.compile(
    r"(?:"
    r"(?<![\w@/])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?::[0-9]{1,5})?(?:/[^\s<>]*)?"
    r"|(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?(?:/[^\s<>]*)?"
    r"|\[(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,39}\](?::[0-9]{1,5})?"
    r"|\blocalhost(?::[0-9]{1,5})?(?:/[^\s<>]*)?"
    r"|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b"
    r")",
    re.IGNORECASE,
)
_OBFUSCATED_NETWORK_DESTINATION = re.compile(
    r"\b[a-z0-9-]{1,63}\s*(?:\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\s+dot\s+)"
    r"\s*[a-z]{2,63}\b",
    re.IGNORECASE,
)
_DOWNLOAD_OR_SHELL = re.compile(
    r"(?:\b(?:curl|wget|aria2c)\b|\|\s*(?:ba|z|k)?sh\b|/(?:usr/)?bin/(?:ba|z|k)?sh\b|"
    r"\b(?:ba|z|k)?sh\s+-[a-z]*c\b|"
    r"\b(?:pacman|yay|paru|makepkg|systemctl|rm|chmod|chown|python[23]?|perl|ruby)\s+-|"
    r"\$\(|`|&&|\bsudo\b)",
    re.IGNORECASE,
)
_EXECUTABLE_INSTRUCTION = re.compile(
    r"(?:^|[.!?:][ \t]+)(?:please[ \t]+)?(?:run|execute|download|install|uninstall|remove|delete|"
    r"edit|write|replace|copy|paste|type|enter|open|visit|click|invoke|launch|start|stop|restart|"
    r"enable|disable|apply|mount|unmount|share|send|upload|provide|submit|forward|attach|export|"
    r"fetch|clone|push|configure|proceed|obtain|supply|reveal|give|tell)[ \t]+",
    re.IGNORECASE,
)
_SENTENCE_LEADING_DIRECTIVE = re.compile(
    r"(?:^|[.!?;:][ \t]+)(?:please[ \t]+|kindly[ \t]+)?(?:run|re-?run|execute|download|install|"
    r"uninstall|remove|delete|edit|write|replace|copy|paste|type|enter|open|visit|click|invoke|"
    r"launch|start|stop|restart|enable|disable|apply|mount|unmount|share|send|upload|provide|"
    r"submit|forward|attach|export|fetch|clone|push|configure|proceed|obtain|supply|reveal|give|"
    r"tell|use|check|inspect|review|verify|confirm|compare|examine|investigate|consult|read|follow|"
    r"select|choose|contact|ask|request|repeat|retry|wait|continue|avoid|keep|save|store|move|"
    r"rename|create|add|change|modify|update|upgrade|connect|navigate|browse|search|look|log|sign|"
    r"authenticate|authorize|scan|test|validate|resolve|fix|repair|remediate|report|notify|respond|"
    r"reply|perform|complete|ensure|take|place|put|refer|switch|turn|go|analyze|assess)\b",
    re.IGNORECASE,
)
_ACTION_VERB = (
    r"(?:run|execute|download|install|uninstall|remove|delete|edit|write|replace|copy|paste|type|"
    r"enter|open|visit|click|invoke|launch|start|stop|restart|enable|disable|apply|mount|unmount|"
    r"share|send|upload|provide|submit|forward|attach|export|fetch|clone|push|configure|set|use|"
    r"build|rebuild|source|evaluate|decode|grant|allow|approve|proceed|obtain|supply|reveal|give|"
    r"tell)"
)
_ACTION_GERUND = (
    r"(?:running|executing|downloading|installing|uninstalling|removing|deleting|editing|writing|"
    r"replacing|copying|pasting|typing|entering|opening|visiting|clicking|invoking|launching|"
    r"starting|stopping|restarting|enabling|disabling|applying|mounting|unmounting|sharing|sending|"
    r"uploading|providing|submitting|forwarding|attaching|exporting|fetching|cloning|pushing|"
    r"configuring|setting|using|building|rebuilding|sourcing|evaluating|decoding|granting|allowing|"
    r"approving|proceeding|obtaining|supplying|revealing|giving|telling)"
)
_ACTION_PARTICIPLE = (
    r"(?:run|executed|downloaded|installed|uninstalled|removed|deleted|edited|written|replaced|"
    r"copied|pasted|typed|entered|opened|visited|clicked|invoked|launched|started|stopped|restarted|"
    r"enabled|disabled|applied|mounted|unmounted|shared|sent|uploaded|provided|submitted|forwarded|"
    r"attached|exported|fetched|cloned|pushed|configured|set|used|built|rebuilt|sourced|evaluated|"
    r"decoded|granted|allowed|approved)"
)
_ACTOR_DIRECTIVE = re.compile(
    r"\b(?:you|your|yours|yourself)\b|"
    r"\b(?:the[ \t]+)?(?:user|users|administrator|administrators|admin|admins|operator|operators|"
    r"maintainer|maintainers|developer|developers|reader|readers|recipient|recipients|one|we|they)"
    r"[ \t]+(?:should|must|ought[ \t]+to|need(?:s)?[ \t]+to|ha(?:ve|s)[ \t]+to|can|could|may|"
    r"might|would)[ \t]+(?:first[ \t]+|then[ \t]+|also[ \t]+|instead[ \t]+|carefully[ \t]+)*"
    + _ACTION_VERB,
    re.IGNORECASE,
)
_ACTIONABLE_RECOMMENDATION = re.compile(
    r"\b(?:please|consider|try(?:[ \t]+to)?|remember[ \t]+to|make[ \t]+sure[ \t]+to)"
    r"[ \t]+(?:first[ \t]+|then[ \t]+|also[ \t]+|instead[ \t]+|carefully[ \t]+)*(?:"
    + _ACTION_VERB
    + "|"
    + _ACTION_GERUND
    + r")|\b(?:it[ \t]+(?:is|would[ \t]+be)[ \t]+)?"
    r"(?:recommended|advisable|necessary|best|safer|helpful|wise|prudent)[ \t]+to[ \t]+"
    + _ACTION_VERB
    + r"|\b(?:next[ \t]+step|solution|fix|remedy|workaround|recommendation|option|approach)"
    r"[ \t]+(?:is|would[ \t]+be)[ \t]+(?:to[ \t]+)?(?:"
    + _ACTION_VERB
    + "|"
    + _ACTION_GERUND
    + r")|\b(?:recommend|suggest|advise)(?:s|d|ing)?[ \t]+(?:that[ \t]+)?(?:"
    + _ACTION_VERB
    + "|"
    + _ACTION_GERUND
    + r")|\b"
    + _ACTION_GERUND
    + r"\b.{0,48}\b(?:recommended|advisable|necessary|best|safer|helpful|wise|prudent)\b|"
    r"\bit[ \t]+(?:can|could|may|might|would)[ \t]+help[ \t]+(?:to[ \t]+)?"
    + _ACTION_VERB
    + r"|\b(?:can|could|may|might|would)[ \t]+(?:want|try)[ \t]+(?:to[ \t]+)?"
    + _ACTION_VERB
    + r"|\b(?:to|in[ \t]+order[ \t]+to)[ \t]+(?:fix|resolve|address|remediate)\b.{0,40}"
    + _ACTION_VERB
    + r"|\b(?:fix|solution|remedy|workaround)\b.{0,32}\b(?:involves|requires)[ \t]+(?:"
    + _ACTION_VERB
    + "|"
    + _ACTION_GERUND
    + r")"
    + r"|\b(?:package|application|app|tool|helper|update|command|script|file|archive|link|installer)"
    r"[ \t]+(?:can|could|may|might|should|must|would)[ \t]+be[ \t]+"
    + _ACTION_PARTICIPLE,
    re.IGNORECASE,
)
_PRESCRIPTIVE_MARKER = re.compile(
    r"\b(?:please|should|must|ought|recommend(?:s|ed|ing|ation)?|suggest(?:s|ed|ing|ion)?|"
    r"advis(?:e|es|ed|ing|able)|encourag(?:e|es|ed|ing)|invit(?:e|es|ed|ing)|consider|"
    r"next[ \t]+step|workaround|remedy|feel[ \t]+free|required|necessary|best|prudent|"
    r"wise|safe[ \t]+to|okay[ \t]+to|acceptable[ \t]+to|appropriate[ \t]+to)\b",
    re.IGNORECASE,
)
_COMMAND_LEADIN = re.compile(
    r"\b(?:command|shell|terminal|console|script|code)[ \t]*(?:is|:|=)[ \t]*\S+",
    re.IGNORECASE,
)
_PACKAGE_HELPER = (
    r"(?:pacman|makepkg|yay|paru|pamac|pikaur|trizen|aurman|apt(?:-get)?|dnf|yum|zypper|apk|"
    r"flatpak|snap|pipx?|uv|npm|pnpm|yarn|cargo|gem)"
)
_PACKAGE_HELPER_ADVICE = re.compile(
    r"\b(?:run|use|try|invoke|execute|launch|start|install|update|upgrade|remove|uninstall|build|"
    r"rebuild)[ \t]+(?:the[ \t]+)?(?:sudo[ \t]+)?(?:/usr/bin/)?"
    + _PACKAGE_HELPER
    + r"\b|\b(?:with|via|through|using)[ \t]+(?:sudo[ \t]+)?(?:/usr/bin/)?"
    + _PACKAGE_HELPER
    + r"\b|\b(?:/usr/bin/)?"
    + _PACKAGE_HELPER
    + r"[ \t]+(?:--?[a-z0-9]|can[ \t]+(?:install|remove|update|upgrade|build)|could[ \t]+(?:install|"
    r"remove|update|upgrade|build)|should[ \t]+(?:install|remove|update|upgrade|build))|"
    r"\b(?:/usr/bin/)?(?:pacman|yay|paru)[ \t]+-?(?:s(?:y{0,2}u?|u)?|r(?:n|ns|s|c)?|u|"
    r"q(?:e|k|l|m|o|s)?)\b",
    re.IGNORECASE,
)
_GENERIC_PACKAGE_MANAGER = (
    r"(?:package[ -]?manager|package[ -]?management(?:[ -](?:tool|client|helper))?|"
    r"aur[ -]?helper|install(?:ation|er)[ -]?helper)"
)
_GENERIC_PACKAGE_MANAGER_ADVICE = re.compile(
    r"\b(?:use|run|invoke|consult|open|launch|start|execute|install|update|upgrade|remove|build|"
    r"rebuild)[ \t]+(?:the[ \t]+|a[ \t]+|an[ \t]+|your[ \t]+)?"
    + _GENERIC_PACKAGE_MANAGER
    + r"\b|\b"
    + _GENERIC_PACKAGE_MANAGER
    + r"\b.{0,48}\b(?:can|could|may|might|will|would)[ \t]+(?:install|update|upgrade|remove|build|"
    r"rebuild|run|resolve|fix|repair|address|remediate)|\b(?:using|invoking|running|installing|updating|"
    r"upgrading|removing|building|rebuilding)[ \t]+(?:with[ \t]+|via[ \t]+|through[ \t]+|using[ \t]+)?"
    r"(?:the[ \t]+|"
    r"a[ \t]+|an[ \t]+)?"
    + _GENERIC_PACKAGE_MANAGER
    + r"\b.{0,48}\b(?:resolves?|fixes?|repairs?|addresses?|remediates?|solves?|corrects?)\b",
    re.IGNORECASE,
)
_NOMINALIZED_ACTIONABLE_OPERATION = re.compile(
    r"\b(?:next|following|subsequent)[ \t]+(?:terminal[ \t]+|shell[ \t]+|package[ -]?manager[ \t]+)?"
    r"(?:operation|invocation|execution|installation|procedure|workflow|action|step)\b|"
    r"\b(?:operation|invocation|execution|installation|procedure|workflow|action|step)\b.{0,64}"
    r"\b(?:consists?[ \t]+of|involves?|requires?)[ \t]+(?:invoking|running|executing|installing|"
    r"using|launching|starting|opening|downloading)|"
    r"\b(?:terminal[ \t]+|shell[ \t]+|package[ -]?manager[ \t]+)?"
    r"(?:operation|invocation|execution|installation|procedure|workflow|action|step)\b.{0,96}"
    r"\b(?:resolves?|fixes?|repairs?|addresses?|remediates?|solves?|corrects?|clears?|restores?)\b",
    re.IGNORECASE,
)
_CREDENTIAL_TERM = (
    r"(?:credential(?:s)?|password(?:s)?|passphrase(?:s)?|token(?:s)?|api[ _-]?key(?:s)?|"
    r"ssh[ _-]?key(?:s)?|private[ _-]?key(?:s)?|secret(?:s)?|cookie(?:s)?|"
    r"authorization[ _-]?header(?:s)?|recovery[ _-]?code(?:s)?)"
)
_CREDENTIAL_TRANSFER_VERB = (
    r"(?:copy|copies|copied|copying|paste|pastes|pasted|pasting|share|shares|shared|sharing|send|"
    r"sends|sent|sending|upload|uploads|uploaded|uploading|provide|provides|provided|providing|"
    r"submit|submits|submitted|submitting|enter|enters|entered|entering|type|types|typed|typing|"
    r"export|exports|exported|exporting|forward|forwards|forwarded|forwarding|attach|attaches|"
    r"attached|attaching|post|posts|posted|posting|transmit|transmits|transmitted|transmitting|"
    r"disclose|discloses|disclosed|disclosing|supply|supplies|supplied|supplying|reveal|reveals|"
    r"revealed|revealing|give|gives|gave|given|giving|tell|tells|told|telling|hand|hands|handed|"
    r"handing)"
)
_CREDENTIAL_TRANSFER = re.compile(
    r"\b"
    + _CREDENTIAL_TRANSFER_VERB
    + r"\b.{0,48}\b"
    + _CREDENTIAL_TERM
    + r"\b|\b"
    + _CREDENTIAL_TERM
    + r"\b.{0,48}\b"
    + _CREDENTIAL_TRANSFER_VERB
    + r"\b",
    re.IGNORECASE,
)
_UNSUPPORTED_STATE_CLAIM = re.compile(
    r"\b(?:machine|system|host|device|computer|package|configuration|merge|repair)\b.{0,24}\b"
    r"(?:safe|secure|clean|trusted|compromised|hacked|breached|infected|owned)\b|"
    r"\b(?:compromised|hacked|breached|infected|owned)\b.{0,16}\b(?:machine|system|host|device|computer)\b|"
    r"\b(?:compromise|breach|infection)\s+(?:is\s+)?(?:confirmed|proven)\b|"
    r"\b(?:no|without)\s+(?:evidence\s+of\s+)?(?:compromise|breach|infection)\b|"
    r"\b(?:uncompromised|malware-free)\b",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|credential|authorization)"
    r"\b\s*[:=]",
    re.IGNORECASE,
)
_BIDI_AND_INVISIBLE = {
    "\u061c",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2060",
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\ufeff",
}


def sanitize_terminal_text(
    value: Any,
    *,
    max_chars: int = 4096,
    single_line: bool = True,
) -> str:
    """Remove terminal controls and visual-order spoofing from display text."""

    text = _ANSI_ESCAPE.sub("", str(value or ""))
    output = []
    for char in text:
        if char in _BIDI_AND_INVISIBLE:
            continue
        category = unicodedata.category(char)
        if category in {"Cc", "Cf"}:
            if not single_line and char == "\n":
                output.append(char)
            elif char in {"\t", "\r", "\n"}:
                output.append(" ")
            continue
        output.append(char)
        if len(output) >= max_chars:
            break
    result = "".join(output)
    if single_line:
        result = _MULTISPACE.sub(" ", result).strip()
    result = _RESERVED_PRODUCT_PREFIX.sub("[untrusted text]", result)
    return result[:max_chars]


def load_strict_json_object(value: Any, *, max_chars: int) -> Dict[str, object]:
    """Parse a bounded JSON object and reject duplicate keys at every level."""

    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise ValueError("AI response was empty or exceeded its size limit")

    def reject_duplicates(pairs: Sequence[Tuple[str, object]]) -> Dict[str, object]:
        result: Dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("AI response contained a duplicate key")
            result[key] = item
        return result

    def reject_nonfinite(_value: str) -> object:
        raise ValueError("AI response contained a non-finite number")

    parsed = json.loads(
        value,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(parsed, dict):
        raise ValueError("AI response was not a JSON object")
    return parsed


def validate_model_advisory_text(
    value: Any,
    *,
    max_chars: int,
    allow_empty: bool = True,
) -> str:
    """Validate one line of non-executable model-authored advisory prose."""

    if not isinstance(value, str):
        raise ValueError("AI advisory text was not a string")
    if len(value) > max_chars:
        raise ValueError("AI advisory text exceeded its size limit")
    raw = value.strip()
    if not raw:
        if allow_empty:
            return ""
        raise ValueError("AI advisory text was empty")
    if _ANSI_ESCAPE.search(raw) or _RESERVED_PRODUCT_PREFIX.search(raw) or _TERMINAL_IMPERSONATION.search(raw):
        raise ValueError("AI advisory text attempted terminal impersonation")
    if any(char in _BIDI_AND_INVISIBLE or unicodedata.category(char) in {"Cc", "Cf"} for char in raw):
        raise ValueError("AI advisory text contained terminal or Unicode controls")
    inspected = unicodedata.normalize("NFKC", raw)
    if _URL.search(inspected) or _BARE_NETWORK_DESTINATION.search(inspected) or _OBFUSCATED_NETWORK_DESTINATION.search(inspected):
        raise ValueError("AI advisory text contained a network destination")
    if (
        _DOWNLOAD_OR_SHELL.search(inspected)
        or _EXECUTABLE_INSTRUCTION.search(inspected)
        or _SENTENCE_LEADING_DIRECTIVE.search(inspected)
        or _ACTOR_DIRECTIVE.search(inspected)
        or _ACTIONABLE_RECOMMENDATION.search(inspected)
        or _PRESCRIPTIVE_MARKER.search(inspected)
        or _COMMAND_LEADIN.search(inspected)
        or _PACKAGE_HELPER_ADVICE.search(inspected)
        or _GENERIC_PACKAGE_MANAGER_ADVICE.search(inspected)
        or _NOMINALIZED_ACTIONABLE_OPERATION.search(inspected)
        or _CREDENTIAL_TRANSFER.search(inspected)
        or "?" in inspected
    ):
        raise ValueError("AI advisory text contained actionable or interactive prose")
    if _UNSUPPORTED_STATE_CLAIM.search(inspected):
        raise ValueError("AI advisory text made an unsupported system-state claim")
    if _SECRET_ASSIGNMENT.search(inspected):
        raise ValueError("AI advisory text contained credential-like data")
    sanitized = sanitize_terminal_text(inspected, max_chars=max_chars, single_line=True)
    if not sanitized and not allow_empty:
        raise ValueError("AI advisory text was empty after sanitization")
    return sanitized


def advisory_text_or_fallback(value: Any, *, max_chars: int, fallback: str) -> str:
    """Return validated advisory prose or a fixed display-safe fallback."""

    if value is None or value == "":
        return ""
    try:
        return validate_model_advisory_text(value, max_chars=max_chars)
    except (TypeError, ValueError):
        return sanitize_terminal_text(fallback, max_chars=max_chars, single_line=True)
