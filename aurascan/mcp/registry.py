"""The tool table: name, schema, annotations, handler and budget.

Order is fixed and visible in ``tools/list``. Every entry earns ``readOnlyHint: true`` on facts —
nothing here writes, and the one process is bounded and disclosed — because Hermes gates MCP tools by
annotation and a headless session declines anything that is not annotated read-only.

The validator below is deliberately narrower than JSON Schema. String ``maxLength`` bounds are
advertised so a client can see them but are enforced by the handlers, which return the stable
``content_too_large`` code; only type, ``required``, ``additionalProperties``, ``minLength``,
``enum``, ``minimum`` and ``maximum`` are decided here.
"""

from .tools import audit_agent_config, scan_content, scan_path, security_audit

HONESTY_LINE = (
    "AuraScan's injection detector is a static, rule-based first signal \u2014 it reports text that "
    "looks like instructions aimed at an AI reader, nothing is executed, and the confidence value "
    "is a policy label, not a precision estimate."
)

_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}

_SCAN_CONTENT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["content"],
    "properties": {
        "content": {"type": "string", "minLength": 0, "maxLength": 262144},
        "source_type": {
            "type": "string",
            "enum": ["documentation", "fixture", "source", "unknown"],
            "default": "unknown",
        },
        "path_hint": {"type": "string", "maxLength": 1024, "default": ""},
        "max_findings": {"type": "integer", "minimum": 1, "maximum": 32, "default": 32},
        "include_snippet": {"type": "boolean", "default": False},
    },
}

_SCAN_PATH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["path"],
    "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": 4096},
        "max_findings": {"type": "integer", "minimum": 1, "maximum": 32, "default": 32},
        "include_snippet": {"type": "boolean", "default": False},
    },
}

_AUDIT_AGENT_CONFIG_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["config"],
    "properties": {
        "config": {"type": "string", "minLength": 1, "maxLength": 262144},
        "surface": {
            "type": "string",
            "enum": [
                "cursor-mcp-manifest",
                "cursor-permissions-configuration",
                "mcp-manifest",
            ],
            "default": "cursor-mcp-manifest",
        },
        "path_hint": {"type": "string", "maxLength": 1024, "default": ""},
    },
}

_SECURITY_AUDIT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "max_findings": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        "include_evidence": {"type": "boolean", "default": False},
    },
}


class Tool(object):
    __slots__ = ("name", "title", "description", "schema", "handler", "budget")

    def __init__(self, name, title, description, schema, handler, budget):
        self.name = name
        self.title = title
        self.description = description
        self.schema = schema
        self.handler = handler
        self.budget = budget

    def listing(self):
        annotations = dict(_ANNOTATIONS)
        annotations["title"] = self.title
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
            "annotations": annotations,
        }


SCAN_CONTENT_DESCRIPTION = (
    "Scan untrusted text for prompt-injection signals. Static and rule-based: the text is never "
    "executed and nothing is fetched or written. `source_type` selects the policy - `unknown` (the "
    "default) behaves like `source` and is the honest reverse-deployment number; pass `fixture` or "
    "`documentation` when you know. `path_hint` only derives the type while `source_type` is "
    "`unknown`. Findings carry no raw text unless `include_snippet` is true. `truncated` is only "
    "reported when `max_findings` is below 32; at 32 the scanner's own per-file cap applies and the "
    "flag is always false. Cancellation cannot be observed before the call returns. " + HONESTY_LINE
)

SCAN_PATH_DESCRIPTION = (
    "Scan one bounded UTF-8 file from disk. The path derives `source_type` and must resolve inside a "
    "configured root. Read-only: the file is read once, nothing is written. Symlinks are followed "
    "only while they stay inside a root; non-regular files are refused. Findings carry no raw text "
    "unless `include_snippet` is true. `truncated` follows the same rule as `scan_content`. " +
    HONESTY_LINE
)

AUDIT_AGENT_CONFIG_DESCRIPTION = (
    "Audit one agent/MCP configuration document as untrusted data. Static: no file is opened, no "
    "command is run, no permission is evaluated. Reports broad tool grants, dangerous hook "
    "correlations, command behaviour correlations and JSON shape problems, with line numbers. It "
    "establishes static configuration only - not that a server starts, a grant is effective, or a "
    "command executes. `mcp-manifest` checks JSON shape and grants only and does not correlate "
    "commands; `cursor-mcp-manifest` (the default) adds command-behaviour correlations and is the "
    "surface to use for any document with `mcpServers` command/args fields. Duplicate keys are "
    "rejected, not last-wins: a document with two `mcpServers` keys reports an invalid-shape finding "
    "and `coverage_complete: false`. " + HONESTY_LINE
)

SECURITY_AUDIT_DESCRIPTION = (
    "Check the local host against bounded AUR campaign intelligence, bundled vendor advisories and "
    "host indicators. Runs in offline mode by design: no network at all, and no state is written - "
    "the campaign feed comes from the packaged assets or a previously refreshed cache, and "
    "`arch-audit` is skipped. It runs one read-only process (`pacman -Q`, bounded to 30 s) and stats "
    "or reads the reported artifact paths under `/etc`, `/usr/lib`, `/usr/bin` and `/usr/local/bin` "
    "(including `/etc/ufw/user.rules` and `/etc/ufw/user6.rules`), `/root/pamkeys`, "
    "`/var/log/pacman.log{,.1}`, `/sys/fs/bpf` and the AUR helper cache. Findings are exposure "
    "evidence: a package-name match is not proof a malicious commit executed, and no match is not "
    "proof of integrity. AuraScan never removes or quarantines anything. The honesty line in "
    "`instructions` applies to the injection detector; this tool additionally runs one read-only "
    "process. `include_evidence` (default false) adds each finding's `evidence` array. That array is "
    "host-local: it carries absolute paths of matched artifacts, `hidden_*` BPF object names and "
    "Tailscale peer markers, so a result pasted into a chat discloses this host's layout. "
    "`arch_audit.findings[].evidence` is not returned at all - the arch audit does not run offline "
    "today, so its evidence is unreachable and must not be assumed."
)

TOOLS = (
    Tool(
        "scan_content",
        "Scan text for prompt-injection signals",
        SCAN_CONTENT_DESCRIPTION,
        _SCAN_CONTENT_SCHEMA,
        scan_content.handle,
        20,
    ),
    Tool(
        "scan_path",
        "Scan one file for prompt-injection signals",
        SCAN_PATH_DESCRIPTION,
        _SCAN_PATH_SCHEMA,
        scan_path.handle,
        20,
    ),
    Tool(
        "audit_agent_config",
        "Audit an agent or MCP configuration document",
        AUDIT_AGENT_CONFIG_DESCRIPTION,
        _AUDIT_AGENT_CONFIG_SCHEMA,
        audit_agent_config.handle,
        20,
    ),
    Tool(
        "security_audit",
        "Audit the local host offline",
        SECURITY_AUDIT_DESCRIPTION,
        _SECURITY_AUDIT_SCHEMA,
        security_audit.handle,
        60,
    ),
)

TOOLS_BY_NAME = dict((tool.name, tool) for tool in TOOLS)

_TYPES = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _type_ok(expected, value):
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    python_type = _TYPES.get(expected)
    return python_type is not None and isinstance(value, python_type)


def validate(schema, arguments):
    """Return one ``"<field>: <reason>"`` string per violation, in schema order."""
    problems = []
    properties = schema.get("properties", {})
    for field in schema.get("required", []):
        if field not in arguments:
            problems.append("%s: is required" % (field,))
    if schema.get("additionalProperties") is False:
        for field in arguments:
            if field not in properties:
                problems.append("%s: is not a known argument" % (field,))
    for field, rule in properties.items():
        if field not in arguments:
            continue
        value = arguments[field]
        expected = rule.get("type")
        if expected and not _type_ok(expected, value):
            problems.append("%s: must be a %s" % (field, expected))
            continue
        if "enum" in rule and value not in rule["enum"]:
            problems.append("%s: must be one of %s" % (field, ", ".join(rule["enum"])))
        if isinstance(value, str) and "minLength" in rule and len(value) < rule["minLength"]:
            problems.append("%s: is shorter than %d characters" % (field, rule["minLength"]))
        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in rule and value < rule["minimum"]:
                problems.append("%s: must be at least %d" % (field, rule["minimum"]))
            if "maximum" in rule and value > rule["maximum"]:
                problems.append("%s: must be at most %d" % (field, rule["maximum"]))
    return problems
