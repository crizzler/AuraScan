"""Privacy redaction: replace host-identifying and secret-bearing text with stable tokens.

This module is the single owner of the privacy transform used before any
incident, recovery or automation text is persisted, printed or sent to a
provider. It replaces credentials, private keys, command fields, home paths,
MAC and IP addresses, the local hostname and the invoking usernames with
deterministic ``<kind:digest>`` correlation tokens.

The tokens are stable for the same input, so correlation survives redaction
without exposing the original value. The transform reads the ambient host
identity (``socket.gethostname()``) and ``USER``/``SUDO_USER``; it never writes,
never resolves a name over the network and never executes anything.
"""

import hashlib
import os
import re
import socket
from typing import Mapping


PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.IGNORECASE)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|credential|authorization)\b\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
AUTHORIZATION_TOKEN_RE = re.compile(r"(?i)(\bauthorization\b\s*[:=]?\s*(?:bearer|basic)\s+)[^\s,;]+")
COMMAND_FIELD_RE = re.compile(r"(?i)(\b(?:COMMAND|CMDLINE|PROCTITLE)\s*=\s*).*$")
HOME_PATH_RE = re.compile(r"/home/([^/\s]+)")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")


def redact_incident_text(text: str) -> str:
    value = str(text or "")
    value = PRIVATE_KEY_RE.sub("<redacted-private-key>", value)
    value = URL_USERINFO_RE.sub(r"\1<redacted-user>:<redacted-password>@", value)
    value = AUTHORIZATION_TOKEN_RE.sub(r"\1<redacted>", value)
    value = SECRET_ASSIGNMENT_RE.sub(r"\1<redacted>", value)
    value = COMMAND_FIELD_RE.sub(r"\1<command-omitted>", value)
    value = HOME_PATH_RE.sub(lambda match: "/home/" + correlation_token("user", match.group(1)), value)
    value = MAC_RE.sub(lambda match: correlation_token("mac", match.group(0).lower()), value)
    value = IPV4_RE.sub(lambda match: correlation_token("ip", match.group(0)), value)
    value = IPV6_RE.sub(lambda match: correlation_token("ip", match.group(0).lower()), value)
    hostname = socket.gethostname().strip()
    if hostname:
        value = re.sub(rf"(?<![\w.-]){re.escape(hostname)}(?![\w.-])", correlation_token("host", hostname), value, flags=re.IGNORECASE)
    usernames = {os.environ.get("USER", "").strip(), os.environ.get("SUDO_USER", "").strip()}
    for username in sorted((item for item in usernames if len(item) >= 2), key=len, reverse=True):
        value = re.sub(rf"(?<![\w.-]){re.escape(username)}(?![\w.-])", correlation_token("user", username), value)
    return value


def correlation_token(kind: str, value: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:8]
    return f"<{kind}:{digest}>"


def redact_structure(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): redact_structure(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return redact_incident_text(value)
    return value
