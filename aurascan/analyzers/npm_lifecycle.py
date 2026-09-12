"""Bounded correlations in a captured npm lifecycle entry point.

This is a deliberately small JavaScript lexical subset, never a JavaScript
interpreter. It binds an exact lifecycle launcher to the same package's captured
root index.js. Literal imports, paths, direct calls, and parameterless local
helpers are supported. Dynamic imports, computed calls, arbitrary data flow,
callbacks, and external modules are not followed. No filesystem or network I/O
is performed here; the caller owns stable no-follow capture and tree limits.
"""

import posixpath
import re
import shlex
import urllib.parse
from typing import Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from aurascan.analyzers.npm_metadata import MetadataIncomplete, strict_json_object
from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source


_MAX_CHARS = 1024 * 1024
_MAX_TOKENS = 65536
_MAX_DEPTH = 64
_MAX_FUNCTIONS = 256
_MAX_EXPRESSION_TOKENS = 4096
_LIFECYCLES = frozenset(("preinstall", "install", "postinstall", "prepare"))
_CREDENTIAL_NAMES = frozenset((
    "NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_AUTH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
    "GITHUB_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
))
_CREDENTIAL_PATHS = (
    ".npmrc", ".git-credentials", ".aws/credentials", ".config/gh/hosts.yml",
    ".config/gcloud/application_default_credentials.json", ".ssh/id_rsa",
    ".ssh/id_ed25519", ".ssh/id_ecdsa",
)
_PERSISTENCE_PATHS = (".vscode/tasks.json", ".claude/settings.json")
_MODULES = frozenset(("fs", "fs/promises", "path", "os", "http", "https", "child_process"))
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


class _Incomplete(ValueError):
    pass


class _Token(NamedTuple):
    kind: str
    value: str
    line: int


class _Function(NamedTuple):
    start: int
    end: int
    body_start: int
    body_end: int
    name: str
    no_parameters: bool


def _string(text: str, start: int) -> Tuple[str, int, bool]:
    quote = text[start]
    index = start + 1
    parts: List[str] = []
    dynamic = False
    while index < len(text):
        char = text[index]
        if char == quote:
            return "".join(parts), index + 1, dynamic
        if quote == "`" and text[index:index + 2] == "${":
            # Interpolation can evaluate arbitrary code. Do not flatten it into
            # an apparently constant path or an apparently active code string.
            dynamic = True
        if char in "\r\n" and quote != "`":
            raise _Incomplete()
        if char != "\\":
            parts.append(char)
            index += 1
            continue
        index += 1
        if index >= len(text):
            raise _Incomplete()
        char = text[index]
        if char in "xu":
            length = 2 if char == "x" else 4
            digits = text[index + 1:index + 1 + length]
            if len(digits) != length or not re.fullmatch(r"[0-9a-fA-F]+", digits):
                raise _Incomplete()
            parts.append(chr(int(digits, 16)))
            index += length + 1
        elif char in "\r\n":
            index += 1
            if char == "\r" and text[index:index + 1] == "\n":
                index += 1
        else:
            parts.append({"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}.get(char, char))
            index += 1
    raise _Incomplete()


def _tokens(text: str) -> List[_Token]:
    if len(text) > _MAX_CHARS:
        raise _Incomplete()
    result: List[_Token] = []
    index = 0
    line = 1
    parens: List[bool] = []
    regex_after_control = False
    while index < len(text):
        start = index
        char = text[index]
        if char.isspace():
            line += char == "\n"
            index += 1
            continue
        if text.startswith("//", index) or (index == 0 and text.startswith("#!")):
            index = text.find("\n", index)
            if index < 0:
                break
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise _Incomplete()
            index = end + 2
            line += text[start:index].count("\n")
            continue
        if char in "\"'`":
            value, index, dynamic = _string(text, index)
            if dynamic:
                raise _Incomplete()
            result.append(_Token("string", value, line))
            line += text[start:index].count("\n")
        elif char == "/" and (not result or regex_after_control or result[-1].value in (
            "=", "(", "[", "{", ",", ":", ";", "!", "&&", "||", "?", "return", "=>", "}",
            "+", "-", "*", "/", "%", "^", "&", "|", "~", "<", ">", "==", "===", "!=", "!==",
            "+=", "-=", "throw", "yield", "await", "case", "in", "of",
        )):
            # Regex bodies are data even if they spell calls or credential names.
            index += 1
            in_class = False
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] in "\r\n":
                    raise _Incomplete()
                if text[index] == "[":
                    in_class = True
                elif text[index] == "]":
                    in_class = False
                elif text[index] == "/" and not in_class:
                    index += 1
                    while index < len(text) and text[index].isalpha():
                        index += 1
                    break
                index += 1
            else:
                raise _Incomplete()
            result.append(_Token("opaque", "", line))
        elif _IDENTIFIER.match(text, index):
            match = _IDENTIFIER.match(text, index)
            assert match is not None
            result.append(_Token("id", match.group(), line))
            index = match.end()
        else:
            value = next((operator for operator in ("===", "!==", "=>", "==", "!=", "&&", "||", "?.", "++", "--", "+=", "-=") if text.startswith(operator, index)), char)
            if value == "(":
                parens.append(bool(result and result[-1].value in ("if", "while", "for", "with", "switch", "catch")))
            regex_after_control = value == ")" and bool(parens and parens.pop())
            result.append(_Token("punct", value, line))
            index += len(value)
        if char != ")":
            regex_after_control = False
        if len(result) > _MAX_TOKENS:
            raise _Incomplete()
    return result


def _pairs(tokens: Sequence[_Token]) -> Dict[int, int]:
    stack: List[int] = []
    result: Dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.kind != "punct":
            continue
        if token.value in ("(", "[", "{"):
            stack.append(index)
            if len(stack) > _MAX_DEPTH:
                raise _Incomplete()
        elif token.value in (")", "]", "}"):
            if not stack:
                raise _Incomplete()
            previous = stack.pop()
            if {"(": ")", "[": "]", "{": "}"}[tokens[previous].value] != token.value:
                raise _Incomplete()
            result[previous] = index
    if stack:
        raise _Incomplete()
    return result


def _arguments(tokens: Sequence[_Token], pairs: Mapping[int, int], start: int) -> List[Tuple[int, int]]:
    end = pairs[start]
    result: List[Tuple[int, int]] = []
    left = start + 1
    index = left
    while index < end:
        if tokens[index].kind == "punct" and tokens[index].value == ",":
            result.append((left, index))
            left = index + 1
        elif index in pairs:
            index = pairs[index]
        index += 1
    if left < end:
        result.append((left, end))
    return result


def _chain(tokens: Sequence[_Token], start: int, end: int) -> Tuple[str, int]:
    if start >= end or tokens[start].kind != "id":
        return "", start
    parts = [tokens[start].value]
    index = start + 1
    while index + 1 < end and tokens[index].value == "." and tokens[index + 1].kind == "id":
        parts.append(tokens[index + 1].value)
        index += 2
    return ".".join(parts), index


def _functions(tokens: Sequence[_Token], pairs: Mapping[int, int]) -> Dict[int, _Function]:
    result: Dict[int, _Function] = {}
    index = 0
    while index < len(tokens):
        if tokens[index].kind == "id" and tokens[index].value == "function":
            cursor = index + 1
            name = ""
            if cursor < len(tokens) and tokens[cursor].kind == "id":
                name = tokens[cursor].value
                cursor += 1
            if cursor not in pairs or tokens[cursor].value != "(":
                raise _Incomplete()
            close = pairs[cursor]
            body = close + 1
            if body not in pairs or tokens[body].value != "{":
                raise _Incomplete()
            # A name inside a function expression is not an outer-scope binding.
            if index and tokens[index - 1].value not in (";", "}", "{", "async", "export", "default"):
                name = ""
            result[index] = _Function(index, pairs[body] + 1, body + 1, pairs[body], name, close == cursor + 1)
        elif tokens[index].kind == "punct" and tokens[index].value == "=>":
            body = index + 1
            if body in pairs and tokens[body].value == "{":
                end = pairs[body] + 1
                body_end = end - 1
                body_start = body + 1
            else:
                end = body
                while end < len(tokens) and tokens[end].value not in (";", ",", ")", "]", "}"):
                    if end in pairs:
                        end = pairs[end]
                    end += 1
                body_start, body_end = body, end
            # Arrow bodies are not presumed to execute merely because they occur
            # in the entry point; callback and closure data flow is unsupported.
            result[index] = _Function(index, end, body_start, body_end, "", False)
        index += 1
        if len(result) > _MAX_FUNCTIONS:
            raise _Incomplete()
    return result


def _literal(tokens: Sequence[_Token], pairs: Mapping[int, int], start: int, end: int,
             bindings: Mapping[str, str], values: Mapping[str, str], depth: int = 0) -> Optional[str]:
    if depth > 16 or start >= end:
        return None
    if start + 1 == end:
        token = tokens[start]
        return token.value if token.kind == "string" else values.get(token.value) if token.kind == "id" else None
    if tokens[start].value == "(" and pairs.get(start) == end - 1:
        return _literal(tokens, pairs, start + 1, end - 1, bindings, values, depth + 1)
    # Only concatenation of separately resolved literal pieces is accepted.
    index = start
    while index < end:
        if tokens[index].value == "+" and tokens[index].kind == "punct":
            left = _literal(tokens, pairs, start, index, bindings, values, depth + 1)
            right = _literal(tokens, pairs, index + 1, end, bindings, values, depth + 1)
            return None if left is None or right is None else left + right
        if index in pairs:
            index = pairs[index]
        index += 1
    name, cursor = _chain(tokens, start, end)
    if name in ("process.env.HOME", "process.env.USERPROFILE") and cursor == end:
        return "~"
    parts = name.split(".")
    resolved = bindings.get(parts[0], parts[0]) + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")
    if cursor in pairs and pairs[cursor] == end - 1:
        arguments = _arguments(tokens, pairs, cursor)
        if resolved == "os.homedir" and not arguments:
            return "~"
        if resolved in ("path.join", "path.resolve") and 1 <= len(arguments) <= 16:
            pieces = [_literal(tokens, pairs, left, right, bindings, values, depth + 1) for left, right in arguments]
            if all(piece is not None for piece in pieces):
                return posixpath.normpath(posixpath.join(*pieces))  # type: ignore[arg-type]
    return None


def _module(value: str) -> Optional[str]:
    normalized = value[5:] if value.startswith("node:") else value
    return normalized if normalized in _MODULES else None


def _binding(tokens: Sequence[_Token], pairs: Mapping[int, int], index: int, end: int,
             bindings: Dict[str, str], values: Dict[str, str]) -> None:
    if tokens[index].kind != "id":
        return
    if tokens[index].value == "import":
        cursor = index + 1
        while cursor < min(end, index + 32) and tokens[cursor].value not in ("from", ";"):
            cursor += 1
        if cursor + 1 < end and tokens[cursor].value == "from" and tokens[cursor + 1].kind == "string":
            module = _module(tokens[cursor + 1].value)
            if module and index + 2 == cursor and tokens[index + 1].kind == "id":
                bindings[tokens[index + 1].value] = module
            elif module and [token.value for token in tokens[index + 1:index + 3]] == ["*", "as"] and index + 4 == cursor:
                bindings[tokens[index + 3].value] = module
            elif module and tokens[index + 1].value == "{" and pairs.get(index + 1) == cursor - 1:
                for left, right in _arguments(tokens, pairs, index + 1):
                    if right == left + 1 and tokens[left].kind == "id":
                        bindings[tokens[left].value] = module + "." + tokens[left].value
                    elif right == left + 3 and tokens[left + 1].value == "as":
                        bindings[tokens[left + 2].value] = module + "." + tokens[left].value
        return
    if tokens[index].value not in ("const", "let", "var") or index + 3 >= end:
        return
    target = index + 1
    if tokens[target].kind == "id":
        bindings.pop(tokens[target].value, None)
        values.pop(tokens[target].value, None)
    assignment = target + 1
    if target in pairs and tokens[target].value == "{":
        assignment = pairs[target] + 1
    if assignment >= end or tokens[assignment].value != "=":
        return
    start = assignment + 1
    right = start
    while right < end and not (tokens[right].kind == "punct" and tokens[right].value in (";", ",")):
        if right - start > _MAX_EXPRESSION_TOKENS:
            raise _Incomplete()
        if right in pairs:
            right = pairs[right]
        right += 1
    if start + 4 == right and tokens[start].value == "require" and tokens[start + 1].value == "(" and tokens[start + 2].kind == "string":
        module = _module(tokens[start + 2].value)
        if module and tokens[target].kind == "id":
            bindings[tokens[target].value] = module
        elif module and tokens[target].value == "{":
            for left, stop in _arguments(tokens, pairs, target):
                if stop == left + 1 and tokens[left].kind == "id":
                    bindings[tokens[left].value] = module + "." + tokens[left].value
                elif stop == left + 3 and tokens[left + 1].value == ":":
                    bindings[tokens[left + 2].value] = module + "." + tokens[left].value
    elif tokens[target].kind == "id":
        literal = _literal(tokens, pairs, start, right, bindings, values)
        if literal is not None:
            values[tokens[target].value] = literal


def _path_matches(value: Optional[str], suffixes: Sequence[str]) -> bool:
    if value is None or "\0" in value:
        return False
    normalized = posixpath.normpath(value.replace("\\", "/"))
    return any(normalized == suffix or normalized.endswith("/" + suffix) for suffix in suffixes)


def _network_host(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return None
        return parsed.hostname.lower().rstrip(".")
    except ValueError:
        return None


def _signals(text: str, malicious_hosts: Optional[Sequence[str]]) -> Tuple[Dict[str, int], bool]:
    tokens = _tokens(text)
    pairs = _pairs(tokens)
    functions = _functions(tokens, pairs)
    top_level = [function for function in functions.values() if not any(
        outer.start < function.start < outer.end for outer in functions.values()
    )]
    named = {function.name: function for function in top_level if function.name}
    if len(named) != sum(bool(function.name) for function in top_level):
        raise _Incomplete()
    signals: Dict[str, int] = {}
    bindings: Dict[str, str] = {}
    values: Dict[str, str] = {}
    pending = [(0, len(tokens), 0)]
    visited = set()
    complete = True
    shadowed = set(named).intersection(("process", "fetch", "Object"))
    # Lexical declarations shadow builtins throughout their scope, including
    # earlier text in the temporal dead zone. Do not mistake a local mock for
    # process.env or the global network client.
    for position, token in enumerate(tokens[:-1]):
        if token.kind == "id" and token.value in ("const", "let", "var", "import") and not any(
            function.start <= position < function.end for function in functions.values()
        ):
            shadowed.add(tokens[position + 1].value)
    while pending:
        start, end, depth = pending.pop(0)
        if depth > 16:
            complete = False
            continue
        index = start
        while index < end:
            token = tokens[index]
            function = functions.get(index)
            if function:
                # Direct no-argument IIFEs are supported; dormant bodies are data
                # until a supported local call provides an execution edge.
                after = function.end
                if after < end and tokens[after].value == ")":
                    after += 1
                if function.no_parameters and after in pairs and tokens[after].value == "(" and pairs[after] == after + 1:
                    pending.append((function.body_start, function.body_end, depth + 1))
                index = function.end
                continue
            _binding(tokens, pairs, index, end, bindings, values)
            if token.kind == "id" and token.value in ("const", "let", "var", "import") and index + 1 < end:
                shadowed.add(tokens[index + 1].value)
            if token.kind != "id" or (index and tokens[index - 1].value in (".", "?.")):
                index += 1
                continue
            chain, cursor = _chain(tokens, index, end)
            if index + 1 < end and tokens[index + 1].value in ("=", "+=", "-=") and (index == 0 or tokens[index - 1].value not in ("const", "let", "var")):
                bindings.pop(token.value, None)
                values.pop(token.value, None)
                shadowed.add(token.value)
            parts = chain.split(".")
            if cursor < end and tokens[cursor].value in ("=", "+=", "-=") and parts[0] in bindings and len(parts) > 1:
                bindings.pop(parts[0], None)
                complete = False
            resolved = bindings.get(parts[0], "")
            if resolved and len(parts) > 1:
                resolved += "." + ".".join(parts[1:])
            if "process" not in shadowed and chain.startswith("process.env.") and parts[-1] in _CREDENTIAL_NAMES:
                following = tokens[cursor].value if cursor < end else ""
                previous = tokens[index - 1].value if index else ""
                if following not in ("=", "+=", "-=", "++", "--") and previous not in ("delete", "typeof"):
                    signals.setdefault("credential access", token.line)
            elif "process" not in shadowed and chain == "process.env" and cursor in pairs and tokens[cursor].value == "[":
                key = _literal(tokens, pairs, cursor + 1, pairs[cursor], bindings, values)
                after = pairs[cursor] + 1
                if key in _CREDENTIAL_NAMES and (after >= end or tokens[after].value not in ("=", "+=", "-=")):
                    signals.setdefault("credential access", token.line)
            if cursor not in pairs or tokens[cursor].value != "(":
                index += 1
                continue
            arguments = _arguments(tokens, pairs, cursor)
            first = _literal(tokens, pairs, *arguments[0], bindings, values) if arguments else None
            if chain in named and chain not in visited:
                visited.add(chain)
                target = named[chain]
                if target.no_parameters:
                    pending.append((target.body_start, target.body_end, depth + 1))
                else:
                    complete = False
            if resolved in ("fs.readFile", "fs.readFileSync", "fs.promises.readFile", "fs/promises.readFile") and _path_matches(first, _CREDENTIAL_PATHS):
                signals.setdefault("credential access", token.line)
            if resolved in ("fs.readdir", "fs.readdirSync", "fs.promises.readdir", "fs/promises.readdir") and _path_matches(first, (".aws", ".ssh", ".config/gcloud")):
                signals.setdefault("credential access", token.line)
            if "Object" not in shadowed and "process" not in shadowed and chain in ("Object.keys", "Object.values", "Object.entries") and arguments and [part.value for part in tokens[arguments[0][0]:arguments[0][1]]] == ["process", ".", "env"]:
                signals.setdefault("credential access", token.line)
            write = resolved in ("fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync", "fs.promises.writeFile", "fs.promises.appendFile", "fs/promises.writeFile", "fs/promises.appendFile")
            destination = first
            if resolved in ("fs.copyFile", "fs.copyFileSync", "fs.rename", "fs.renameSync", "fs.promises.copyFile", "fs.promises.rename", "fs/promises.copyFile", "fs/promises.rename") and len(arguments) >= 2:
                write = True
                destination = _literal(tokens, pairs, *arguments[1], bindings, values)
            if write and _path_matches(destination, _PERSISTENCE_PATHS):
                signals.setdefault("editor or agent configuration write", token.line)
            if write and destination in ("package.json", "./package.json"):
                signals.setdefault("package manifest write", token.line)
            if (chain == "fetch" and "fetch" not in shadowed) or resolved in ("http.request", "http.get", "https.request", "https.get"):
                host = _network_host(first)
                if host:
                    signals.setdefault("outbound network call", token.line)
                    if malicious_hosts is None:
                        from aurascan.analyzers.npm_supply_chain import known_malicious_npm_host
                        malicious = known_malicious_npm_host(first)
                    else:
                        malicious = host in malicious_hosts
                    if malicious:
                        signals.setdefault("confirmed malicious network destination", token.line)
            if resolved in ("child_process.execFile", "child_process.execFileSync", "child_process.spawn", "child_process.spawnSync") and first in ("npm", "/usr/bin/npm") and len(arguments) >= 2:
                left, right = arguments[1]
                if left in pairs and tokens[left].value == "[" and pairs[left] == right - 1:
                    argv = [_literal(tokens, pairs, begin, stop, bindings, values) for begin, stop in _arguments(tokens, pairs, left)]
                    if argv and argv[0] == "publish":
                        signals.setdefault("npm publication command", token.line)
            index += 1
    return signals, complete


def _finding(rule_id: str, path: str, severity: Severity, explanation: str,
             labels: Sequence[str], line: Optional[int] = None, coverage: bool = False) -> Finding:
    return Finding(
        rule_id=rule_id, package_name="unknown", package_version="unknown",
        phase=Phase.unpacked_source_scan, source=Source.deterministic_rule,
        severity=severity, confidence=Confidence.HIGH,
        evidence_quality=EvidenceQuality.strong_heuristic,
        file_path=path, explanation=explanation,
        recommendation="Review the captured lifecycle entry point and its provenance before building or installing; static evidence does not establish execution or compromise.",
        blocks_installation=coverage or severity == Severity.CRITICAL,
        requires_manual_review=not coverage and severity != Severity.CRITICAL,
        evidence_snippet="; ".join(labels), line_number=line,
        false_positive_notes="Only supported literal calls and captured same-package entry points are correlated. Legitimate credential use can require review; dynamic code and external modules are not followed.",
    )


def inspect_npm_lifecycle(manifest_path: str, manifest_text: str,
                          scripts: Mapping[str, str], *,
                          malicious_hosts: Optional[Sequence[str]] = None,
                          intelligence_snapshot=None) -> List[Finding]:
    """Inspect exact root index.js lifecycle launches using already captured data.

    ``scripts`` must map exact absolute captured paths to text. Other packages
    and siblings are never consulted. ``malicious_hosts`` is a test override;
    production uses only the supplied operation snapshot (or bundled baseline).
    """
    if malicious_hosts is None:
        from aurascan.analyzers.npm_supply_chain import malicious_domains
        malicious_hosts = malicious_domains(intelligence_snapshot)

    def incomplete() -> List[Finding]:
        return [_finding(
            "NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001", manifest_path, Severity.HIGH,
            "A declared npm lifecycle entry point could not be completely inspected within the supported static bounds.",
            ("bounded lifecycle inspection incomplete",), coverage=True,
        )]

    if len(manifest_text) > _MAX_CHARS:
        return incomplete()
    try:
        manifest = strict_json_object(manifest_text)
    except (MetadataIncomplete, ValueError, RecursionError):
        return incomplete()
    hooks = manifest.get("scripts", {})
    if not isinstance(hooks, dict):
        return incomplete()
    selected = False
    for name in _LIFECYCLES:
        command = hooks.get(name)
        if command is None:
            continue
        if not isinstance(command, str):
            return incomplete()
        try:
            words = shlex.split(command, comments=False, posix=True)
        except ValueError:
            return incomplete()
        if words in (["bun", "run", "index.js"], ["bun", "run", "./index.js"],
                     ["bun", "index.js"], ["bun", "./index.js"],
                     ["node", "index.js"], ["node", "./index.js"]):
            selected = True
    if not selected:
        return []
    if not posixpath.isabs(manifest_path) or posixpath.basename(manifest_path) != "package.json" or posixpath.normpath(manifest_path) != manifest_path:
        return incomplete()
    target = posixpath.join(posixpath.dirname(manifest_path), "index.js")
    text = scripts.get(target)
    if not isinstance(text, str):
        return incomplete()
    try:
        signals, complete = _signals(text, malicious_hosts)
    except _Incomplete:
        return incomplete()
    findings = [] if complete else incomplete()
    credential = "credential access" in signals
    persistence = "editor or agent configuration write" in signals
    network = "outbound network call" in signals
    publish = "npm publication command" in signals
    propagation = publish and "package manifest write" in signals
    critical = "confirmed malicious network destination" in signals or (credential and persistence and (network or publish)) or (credential and propagation)
    if critical:
        findings.append(_finding(
            "NPM-LIFECYCLE-SUPPLYCHAIN-001", target, Severity.CRITICAL,
            "A declared npm lifecycle launcher reaches a captured entry point with correlated supply-chain indicators. Static evidence does not establish execution, campaign attribution, or compromise.",
            ("exact package-root lifecycle launcher",) + tuple(sorted(signals)), min(signals.values()),
        ))
        return findings
    if credential:
        findings.append(_finding(
            "NPM-LIFECYCLE-CREDENTIAL-ACCESS-001", target, Severity.HIGH,
            "A declared npm lifecycle entry point contains supported credential-file, authentication-environment, or credential-directory access. Its purpose requires manual review; theft or execution is not established.",
            ("exact package-root lifecycle launcher", "credential access"), signals["credential access"],
        ))
    if persistence and (credential or network or publish):
        findings.append(_finding(
            "NPM-LIFECYCLE-PERSISTENCE-001", target, Severity.HIGH,
            "A declared npm lifecycle entry point writes editor or agent configuration alongside credential access, networking, or package publication. This can create a persistence opportunity but does not establish activation or compromise.",
            ("exact package-root lifecycle launcher",) + tuple(sorted(signals)), signals["editor or agent configuration write"],
        ))
    return findings
