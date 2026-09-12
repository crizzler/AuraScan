"""Bounded, data-only npm campaign intelligence.

Package declarations and supported shell install arguments identify a selected
release, not successful installation. Only an exact captured-byte digest matches
the payload signature. Registry availability never supplies a trust decision.
"""

import hashlib
import json
import posixpath
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aurascan.analyzers.npm_metadata import (
    MAX_DEPTH, MAX_NODES, MAX_SCALAR, MetadataIncomplete, strict_json_object,
)
from aurascan.analyzers.remote_stage import _commands_and_constants
from aurascan.core.intelligence import IntelligenceSnapshot, bundled_snapshot
from aurascan.core.models import (
    Confidence, EvidenceQuality, Finding, Phase, Severity, Source,
)


# Compatibility exports describe only the shipped baseline. Production matches
# always use the operation's immutable snapshot, never mutable global tables.
_BASELINE = bundled_snapshot()
MALICIOUS_PACKAGES = {
    entry["name"]: entry for campaign in _BASELINE.payload["npm_campaigns"]
    for entry in campaign["packages"]
}
KNOWN_PAYLOAD_SHA256 = frozenset(
    digest for campaign in _BASELINE.payload["npm_campaigns"]
    for digest in campaign["payload_sha256"]
)
_SHAIHULUD_CAMPAIGN = "NPM-2026-09-07-SHAI-HULUD"


def _campaigns(snapshot: Optional[IntelligenceSnapshot]):
    return (snapshot if snapshot is not None else _BASELINE).payload["npm_campaigns"]


_DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z", re.I)
_INSTALL_COMMANDS = {
    "npm": {"install", "i", "add", "install-test", "it"},
    "bun": {"install", "i", "add"},
    "yarn": {"add"},
    "pnpm": {"install", "i", "add"},
}
_VALUE_OPTIONS = {
    "--registry", "--cache", "--prefix", "--userconfig", "--globalconfig",
    "--workspace", "-w", "--filter", "-F", "--dir", "-C", "--cwd",
    "--modules-folder", "--mutex", "--network-timeout", "--network-concurrency",
    "--child-concurrency", "--store-dir",
    "--virtual-store-dir", "--config", "--backend", "--omit", "--include",
    "--tag", "--access", "--save-prefix", "--loglevel", "--fetch-retries",
}
_FLAG_OPTIONS = {
    "-g", "--global", "-D", "--save-dev", "-P", "--save-prod", "--production",
    "-O", "--save-optional", "-E", "--save-exact", "--save", "--no-save",
    "--ignore-scripts", "--no-ignore-scripts", "--ignore-platform", "--ignore-engines",
    "--frozen-lockfile", "--no-frozen-lockfile", "--lockfile-only", "--package-lock-only",
    "--no-package-lock", "--no-audit", "--no-fund", "--audit", "--fund",
    "--legacy-peer-deps", "--strict-peer-deps", "--force", "-f", "--prefer-offline",
    "--offline", "--ignore-optional", "--no-optional", "--optional", "--dev",
    "--no-progress", "--silent", "--quiet", "-s", "--verbose", "--dry-run",
    "--non-interactive", "--recursive", "-r", "--workspace-root", "--trust",
    "--link-workspace-packages",
}


def malicious_domains(intelligence_snapshot: Optional[IntelligenceSnapshot] = None) -> Tuple[str, ...]:
    """Return exact reviewed host indicators without resolving or contacting them."""
    return tuple(sorted({host for campaign in _campaigns(intelligence_snapshot)
                         for host in campaign["malicious_domains"]}))


def _network_host(value: str) -> Optional[str]:
    if not isinstance(value, str) or not value or len(value) > MAX_SCALAR:
        return None
    if "\\" in value or any(ord(char) < 33 or ord(char) == 127 for char in value):
        return None
    try:
        if "://" in value:
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"}:
                return None
            host = parsed.hostname
            parsed.port
        else:
            if any(char in value for char in "/:@?#\\"):
                return None
            host = value
    except ValueError:
        return None
    if host and host.endswith("."):
        host = host[:-1]
    return host.lower() if host else None


def known_malicious_npm_host(value: str, intelligence_snapshot: Optional[IntelligenceSnapshot] = None) -> bool:
    """Match an actual HTTP(S) URL host or bare hostname, never a substring."""
    host = _network_host(value)
    return bool(host and host in malicious_domains(intelligence_snapshot))


def _finding(rule_id: str, path: str, phase: Phase, severity: Severity,
             explanation: str, evidence: str, *, line: Optional[int] = None,
             coverage: bool = False, signature: bool = False) -> Finding:
    critical = severity == Severity.CRITICAL
    return Finding(
        rule_id=rule_id, package_name="unknown", package_version="unknown",
        phase=phase, source=Source.deterministic_rule, severity=severity,
        confidence=Confidence.CONFIRMED if critical or coverage else Confidence.HIGH,
        evidence_quality=(EvidenceQuality.confirmed_signature if signature else
                          EvidenceQuality.confirmed_static_pattern if critical else
                          EvidenceQuality.strong_heuristic),
        file_path=path, line_number=line, evidence_snippet=evidence,
        explanation=explanation,
        recommendation=(
            "Do not build or install until the captured source and dependency provenance have "
            "been independently reviewed. Registry availability and disabled lifecycle scripts "
            "do not establish trust."
        ),
        false_positive_notes=(
            "Static evidence does not establish execution or host compromise. "
            "An advisory package match does not authenticate the captured file contents."
        ),
        blocks_installation=critical or coverage,
        requires_manual_review=not (critical or coverage),
    )


def _selection_findings(name: str, version: str, path: str, phase: Phase,
                        line: Optional[int] = None,
                        intelligence_snapshot: Optional[IntelligenceSnapshot] = None) -> List[Finding]:
    findings = []
    prefix = "DEEPSTATIC" if phase == Phase.unpacked_source_scan else "SUPPLYCHAIN"
    for campaign in _campaigns(intelligence_snapshot):
        for entry in campaign["packages"]:
            if entry["name"] != name:
                continue
            exact = version in entry["versions"]
            if not exact and entry["broad_advisory"] != "all_versions":
                # Exact-only evidence cannot establish a different version's
                # maliciousness or invent an all-version advisory.
                continue
            legacy = campaign["id"] == _SHAIHULUD_CAMPAIGN
            if exact:
                rule = prefix + ("-NPM-SHAIHULUD-20260907" if legacy else "-NPM-MALICIOUS-RELEASE-001")
                explanation = (
                    "A captured npm package selection exactly matches an observed malicious "
                    "release: " + name + "@" + version + ". Reviewed campaign: " + campaign["id"] +
                    ". This is static selection evidence; no installation or execution was observed."
                )
            else:
                rule = prefix + ("-NPM-SHAIHULUD-REVIEW-001" if legacy else "-NPM-ADVISORY-REVIEW-001")
                explanation = (
                    "A captured selection names " + name + ", whose referenced malware advisories "
                    "cover all versions with no patched release. Its version is unresolved or "
                    "differs from the separately observed campaign releases. This requires provenance "
                    "review; it does not confirm the identical payload or establish execution. "
                    "Other versions are not assumed safe. Reviewed campaign: " + campaign["id"] + "."
                )
            findings.append(_finding(
                rule, path, phase, Severity.CRITICAL if exact else Severity.HIGH,
                explanation, "reviewed npm malware advisory: " + ", ".join(entry["advisory_ids"]),
                line=line,
            ))
    return findings


def _selector(name: str, value: str) -> Tuple[str, str]:
    # An npm alias's key is its local installation name, not the real package.
    if value.startswith("npm:"):
        actual, version = _split_spec(value)
        if not actual:
            raise MetadataIncomplete("unsupported npm alias")
        return actual, version
    return name, value


def _split_spec(value: str) -> Tuple[str, str]:
    if len(value) > MAX_SCALAR:
        raise MetadataIncomplete("npm selector bound")
    if "@npm:" in value:
        alias, value = value.split("@npm:", 1)
        if not _NAME.fullmatch(alias):
            return "", ""
    if value.startswith("npm:"):
        value = value[4:]
    if "@npm:" in value or value.startswith("npm:"):
        raise MetadataIncomplete("unsupported nested npm alias")
    index = value.find("@", 1 if value.startswith("@") else 0)
    name, version = (value[:index], value[index + 1:]) if index >= 0 else (value, "")
    if not _NAME.fullmatch(name):
        return "", ""
    return name, version


def _install_specs(arguments: Sequence[str], executable: str) -> Optional[List[str]]:
    if not any(value in _INSTALL_COMMANDS[executable] for value in arguments):
        return []
    command_seen = False
    positional = False
    specs = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        index += 1
        if token == "--":
            positional = True
            continue
        if not positional and token.startswith("-"):
            if token in {"--help", "-h", "--version", "-v"}:
                return []
            option, separator, _value = token.partition("=")
            if executable == "pnpm" and option == "-w" and not separator:
                continue
            if option in _VALUE_OPTIONS:
                if not separator:
                    if index >= len(arguments):
                        return None
                    index += 1
                continue
            if option in _FLAG_OPTIONS:
                continue
            # Unknown option arity cannot establish that its following token is
            # an installed package. Preserve this as coverage, never a match.
            return None
        if token in {">", ">>", "1>", "2>", "1>>", "2>>", "<", "0<"}:
            if index >= len(arguments):
                return None
            index += 1
            continue
        if re.match(r"^[0-9]*[<>]", token):
            continue
        if not command_seen:
            if token not in _INSTALL_COMMANDS[executable]:
                return []
            command_seen = True
        else:
            specs.append(token)
    return specs


def _network_destinations(arguments: Sequence[str], executable: str) -> Optional[List[str]]:
    if executable == "curl":
        values = {
            "--output", "--output-dir", "--data", "--data-raw", "--data-binary",
            "--data-urlencode", "--form", "--form-string", "--header", "--request",
            "--user", "--proxy", "--proxy-user", "--user-agent", "--referer", "--cookie",
            "--cookie-jar", "--connect-timeout", "--max-time", "--retry", "--retry-delay",
            "--config", "--upload-file", "--cacert", "--capath", "--cert", "--key",
            "--resolve", "--connect-to", "--write-out", "--range", "--interface",
            "-o", "-d", "-F", "-H", "-X", "-u", "-x", "-U", "-A", "-e",
            "-b", "-c", "-m", "-K", "-T", "-E", "-w", "-r",
        }
        flags = {
            "--fail", "--fail-with-body", "--silent", "--show-error", "--location",
            "--location-trusted", "--insecure", "--compressed", "--head", "--get",
            "--remote-name", "--remote-header-name", "--create-dirs", "--globoff",
            "--ipv4", "--ipv6", "--http1.1", "--http2", "--no-progress-meter",
            "--verbose", "--disable", "--netrc", "--netrc-optional",
        }
        short_flags = set("fsSLkIOJgG46vqN")
    else:
        values = {
            "--output-document", "--output-file", "--append-output", "--directory-prefix",
            "--input-file", "--user-agent", "--header", "--post-data", "--post-file",
            "--method", "--body-data", "--body-file", "--user", "--password",
            "--http-user", "--http-password", "--proxy-user", "--proxy-password",
            "--timeout", "--tries", "--wait", "--execute", "--load-cookies",
            "--save-cookies", "--referer", "--ca-certificate", "--certificate",
            "--private-key", "--config", "--domains", "--exclude-domains",
            "-O", "-o", "-a", "-P", "-i", "-U", "-T", "-t", "-w", "-e", "-D",
        }
        flags = {
            "--quiet", "--no-verbose", "--verbose", "--continue", "--no-check-certificate",
            "--spider", "--server-response", "--recursive", "--no-parent", "--timestamping",
            "--page-requisites", "--convert-links", "--no-cookies", "--content-disposition",
            "--trust-server-names", "--no-clobber", "--no-proxy", "--ipv4-only", "--ipv6-only",
        }
        short_flags = set("qvcSrNpk46")
    result = []
    positional = False
    index = 0
    while index < len(arguments):
        token = arguments[index]
        index += 1
        if token == "--":
            positional = True
            continue
        if token in {">", ">>", "1>", "2>", "1>>", "2>>", "<", "0<"}:
            if index >= len(arguments):
                return None
            index += 1
            continue
        if re.match(r"^[0-9]*[<>]", token):
            continue
        if not positional and token.startswith("--"):
            if token in {"--help", "--version"}:
                return []
            option, separator, value = token.partition("=")
            if option in values or (option == "--url" and executable == "curl"):
                if not separator:
                    if index >= len(arguments):
                        return None
                    value = arguments[index]
                    index += 1
                if option == "--url":
                    result.append(value)
                continue
            if option in flags and not separator:
                continue
            return None
        if not positional and token.startswith("-") and token != "-":
            offset = 1
            while offset < len(token):
                option = "-" + token[offset]
                if option in {"-h", "-V"}:
                    return []
                if option in values:
                    if offset + 1 == len(token):
                        if index >= len(arguments):
                            return None
                        index += 1
                    break
                if token[offset] not in short_flags:
                    return None
                offset += 1
            continue
        result.append(token)
    return result


def analyze_npm_install_commands(text: str, file_path: str, phase: Phase,
                                 intelligence_snapshot: Optional[IntelligenceSnapshot] = None) -> List[Finding]:
    """Inspect only caller-selected shell controls, never general JS or prose."""
    parsed = _commands_and_constants(text)
    if parsed is None:
        return [_finding(
            "SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001", str(file_path), phase, Severity.HIGH,
            "Package control text exceeded the supported bounded shell grammar while npm "
            "campaign selections were inspected. Missing coverage is not a malware claim.",
            "bounded npm install-command inspection incomplete", coverage=True,
        )]
    findings = []
    seen = set()
    for command in parsed[0]:
        executable = posixpath.basename(command.executable)
        if executable in {"curl", "wget"}:
            destinations = _network_destinations(command.arguments, executable)
            if destinations is None and any(
                value.lower().startswith(("http://", "https://"))
                and known_malicious_npm_host(value, intelligence_snapshot) for value in command.arguments
            ):
                findings.append(_finding(
                    "SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001", str(file_path), phase,
                    Severity.HIGH,
                    "A network command contains a known campaign URL but unsupported options "
                    "leave its argument role unresolved. This is incomplete inspection, not a "
                    "confirmed destination or successful contact.",
                    "campaign URL argument role could not be established",
                    line=command.line_number, coverage=True,
                ))
            if destinations is not None:
                hosts = {_network_host(value) for value in destinations
                         if value.lower().startswith(("http://", "https://"))}
                for campaign in _campaigns(intelligence_snapshot):
                    if not hosts.intersection(campaign["malicious_domains"]):
                        continue
                    legacy = campaign["id"] == _SHAIHULUD_CAMPAIGN
                    prefix = "DEEPSTATIC" if phase == Phase.unpacked_source_scan else "SUPPLYCHAIN"
                    findings.append(_finding(
                        prefix + ("-NPM-SHAIHULUD-C2-001" if legacy else "-NPM-MALICIOUS-DESTINATION-001"),
                        str(file_path), phase, Severity.CRITICAL,
                        "A static network command targets an exact reviewed malicious hostname. "
                        "Reviewed campaign: " + campaign["id"] + ". This establishes a literal "
                        "destination match, not successful contact or host compromise.",
                        "active network destination matches reviewed malicious hostname",
                        line=command.line_number,
                    ))
        if executable not in _INSTALL_COMMANDS:
            continue
        specs = _install_specs(command.arguments, executable)
        if specs is None:
            findings.append(_finding(
                "SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001", str(file_path), phase, Severity.HIGH,
                "An npm-family command uses options whose argument boundaries could not be "
                "resolved statically. Missing coverage is not evidence of malicious behavior.",
                "npm install-command option boundaries incomplete", line=command.line_number,
                coverage=True,
            ))
            continue
        for spec in specs:
            try:
                name, version = _split_spec(spec)
            except MetadataIncomplete:
                findings.append(_finding(
                    "SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001", str(file_path), phase,
                    Severity.HIGH, "An npm selector exceeds the supported bounded literal "
                    "grammar. Missing coverage is not a malware claim.",
                    "npm install-command selector inspection incomplete",
                    line=command.line_number, coverage=True,
                ))
                continue
            key = (name, version, command.line_number)
            if key in seen:
                continue
            seen.add(key)
            matches = _selection_findings(name, version, str(file_path), phase,
                                          command.line_number, intelligence_snapshot)
            findings.extend(matches)
            if not matches and ("$" in spec or "`" in spec):
                findings.append(_finding(
                    "SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001", str(file_path), phase,
                    Severity.HIGH,
                    "An npm install selector is indirect and could not be bound to a literal "
                    "package identity. The scanner does not evaluate shell expansions; this "
                    "is missing coverage, not a known-malicious package match.",
                    "indirect npm install selector requires independent inspection",
                    line=command.line_number, coverage=True,
                ))
    return findings


def _bounded_document(text: str) -> Dict[str, Any]:
    data = strict_json_object(text)
    pending = [(data, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise MetadataIncomplete("metadata structure bound")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
            pending.extend((key, depth + 1) for key in value)
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str) and len(value) > MAX_SCALAR:
            raise MetadataIncomplete("metadata scalar bound")
    return data


def _dependency_selections(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    selected = []
    for field in _DEPENDENCY_FIELDS:
        if field not in data:
            continue
        values = data[field]
        if not isinstance(values, dict):
            raise MetadataIncomplete("dependency mapping")
        for name, value in values.items():
            if not isinstance(value, str) or not _NAME.fullmatch(name):
                raise MetadataIncomplete("dependency selector")
            selected.append(_selector(name, value))
    return selected


def _own_selection(data: Dict[str, Any], fallback_name: str = "", *,
                   alias_version: bool = False) -> List[Tuple[str, str]]:
    name = data.get("name", fallback_name)
    version = data.get("version", "")
    if not isinstance(name, str) or not isinstance(version, str):
        raise MetadataIncomplete("package identity")
    if alias_version:
        return [_selector(name, version)] if name else []
    if version.startswith("npm:"):
        raise MetadataIncomplete("alias is not an own package version")
    return [(name, version)] if name else []


def _locked_name(path: str) -> str:
    parts = path.split("/")
    # npm lockfile packages may also contain workspace locations. They carry
    # an explicit name when relevant; never infer a name from that directory.
    if "node_modules" not in parts:
        return ""
    if any(part in {"", ".", ".."} for part in parts) or "\\" in path:
        raise MetadataIncomplete("locked dependency path")
    last = len(parts) - 1 - parts[::-1].index("node_modules")
    name = "/".join(parts[last + 1:])
    if not _NAME.fullmatch(name):
        raise MetadataIncomplete("locked dependency name")
    return name


def _lockfile_selections(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    version = data.get("lockfileVersion")
    if type(version) is not int or version not in {1, 2, 3}:
        raise MetadataIncomplete("unsupported npm lockfile version")
    selected = _own_selection(data)
    if "packages" in data:
        packages = data["packages"]
        if not isinstance(packages, dict):
            raise MetadataIncomplete("locked package mapping")
        for path, entry in packages.items():
            if not isinstance(entry, dict):
                raise MetadataIncomplete("locked package entry")
            selected.extend(_own_selection(entry, _locked_name(path) if path else ""))
            selected.extend(_dependency_selections(entry))
    elif version in {2, 3}:
        raise MetadataIncomplete("missing locked package mapping")
    legacy = data.get("dependencies", {})
    if not isinstance(legacy, dict):
        raise MetadataIncomplete("legacy dependency mapping")
    pending = list(legacy.items())
    while pending:
        name, entry = pending.pop()
        if not isinstance(entry, dict):
            raise MetadataIncomplete("legacy dependency entry")
        selected.extend(_own_selection(entry, name, alias_version=True))
        children = entry.get("dependencies", {})
        if not isinstance(children, dict):
            raise MetadataIncomplete("legacy dependency children")
        pending.extend(children.items())
    return selected


def inspect_npm_campaign_metadata(path: str, text: str,
                                  intelligence_snapshot: Optional[IntelligenceSnapshot] = None) -> List[Finding]:
    """Read selected package identities from strict package.json/npm lock data."""
    path = str(path)
    if posixpath.basename(path) not in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        return []
    try:
        data = _bounded_document(text)
        if posixpath.basename(path) == "package.json":
            selected = _own_selection(data) + _dependency_selections(data)
        else:
            selected = _lockfile_selections(data)
    except (MetadataIncomplete, RecursionError, UnicodeError):
        return [_finding(
            "NPM-METADATA-INSPECTION-INCOMPLETE-001", path, Phase.unpacked_source_scan,
            Severity.HIGH,
            "npm campaign metadata could not be inspected as bounded, unambiguous package "
            "identity and dependency fields. Missing coverage is not a malware claim.",
            "bounded npm campaign metadata inspection incomplete", coverage=True,
        )]
    findings = []
    seen = set()
    for name, version in selected:
        if (name, version) in seen:
            continue
        seen.add((name, version))
        findings.extend(_selection_findings(name, version, path, Phase.unpacked_source_scan,
                                            intelligence_snapshot=intelligence_snapshot))
    return findings


def known_payload_digest_findings(path: str, digest_hex: str,
                                  intelligence_snapshot: Optional[IntelligenceSnapshot] = None) -> List[Finding]:
    """Match a digest computed by a bounded, stable reader, never a text claim."""
    findings = []
    for campaign in _campaigns(intelligence_snapshot):
        if digest_hex not in campaign["payload_sha256"]:
            continue
        legacy = campaign["id"] == _SHAIHULUD_CAMPAIGN
        finding = _finding(
            "DEEPSTATIC-NPM-SHAIHULUD-PAYLOAD-001" if legacy else "DEEPSTATIC-NPM-MALICIOUS-PAYLOAD-001",
            str(path), Phase.unpacked_source_scan, Severity.CRITICAL,
            "Captured source bytes have the exact SHA-256 of a reviewed malicious payload. "
            "Reviewed campaign: " + campaign["id"] + ". This confirms a payload signature "
            "match, not execution or host compromise.",
            "exact captured-byte malicious payload SHA-256 match", signature=True,
        )
        finding.file_hash = digest_hex
        findings.append(finding)
    return findings


def known_payload_findings(path: str, payload: bytes,
                           intelligence_snapshot: Optional[IntelligenceSnapshot] = None) -> List[Finding]:
    """Hash already bounded captured bytes without parsing or executing them."""
    return known_payload_digest_findings(path, hashlib.sha256(payload).hexdigest(), intelligence_snapshot)
