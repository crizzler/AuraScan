#!/usr/bin/env python3
"""AuraScan architecture audit.

Purpose
-------
Report structural facts about the AuraScan package so a human reviewer can see
where trust, policy and side effects live without reading the entire
application. This is the maintainer tool behind ``docs/ARCHITECTURE.md`` and
``docs/SECURITY_BOUNDARIES.md``.

This tool is intentionally passive and offline:

* it only parses local Python source with :mod:`ast`;
* it never imports ``aurascan``, never executes candidate content, never runs a
  package manager, and never touches the network;
* it does not grade module size. A large module is reported, not failed. The
  module-responsibility budget below is advisory and never changes the exit
  status.

Exit status
-----------
``0``  report produced. Advisory findings (budget warnings) may still be present.
``1``  a blocking architecture invariant failed (``--strict``), or the audit
       could not read its inputs (always).

How capabilities are detected
-----------------------------
Capabilities are derived from *call sites and imports*, resolved through each
module's own import aliases (``import subprocess as sp`` -> ``sp.run`` is
``subprocess.run``; ``from subprocess import run`` -> ``run`` is
``subprocess.run``). A small, explicit attribute table covers path-like methods
whose receiver cannot be resolved statically (``write_text``, ``rmtree``, ...).

These tags describe the shape of the code, not proof of reachability: a module
can also perform an effect indirectly through an adapter it calls. Absence of a
tag is not a claim of purity, and presence of a tag is not a finding.

The attribute fallback deliberately excludes ambiguous names such as ``replace``
and ``write``, which are far more often string or file-object operations than
functional path mutation. A call through an unresolvable receiver can therefore
be missed; the explicit ``os.*``/``pathlib.*``/``shutil.*`` entries cover the
resolvable cases.

Invariants
----------
Invariants are narrow, mechanically checkable architecture or security
boundaries. Each has an explicit, documented allowlist where an exception is
deliberate. Invariants are the only reason this tool ever exits non-zero.
"""

import argparse
import ast
import json
import re
import sys
import sysconfig
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKAGE_ROOT = ROOT / "aurascan"

# Role definitions are written as dotted suffixes so the audit can run against
# any package, including temporary fixtures in tests.

# Domain evidence and pure policy modules.
DOMAIN_SUFFIXES = (
    "core.models",
    "core.risk",
    "core.text_safety",
    "core.update_policy",
)

# The stable rule catalog and its user-facing explanation templates. AGENTS.md
# groups ``rule_metadata.py`` and ``presenter.py`` as one catalog layer; the rule
# IDs legitimately live here, so they are catalog rather than UI modules.
CATALOG_SUFFIXES = (
    "core.rule_metadata",
    "core.presenter",
)

# User-facing entry points. These consume application APIs and must never be
# imported by core application code, analysis or adapters.
UI_ENTRY_SUFFIXES = (
    "cli",
    "setup_wizard",
    "makepkg_wrapper",
    "core.updater_tray",
    "core.intelligence_tray",
    "core.instruction_cli",
    "core.intelligence_cli",
    "core.recovery_cli",
)


def _qualify(package_name: str, suffixes: Sequence[str]) -> Tuple[str, ...]:
    return tuple("{0}.{1}".format(package_name, suffix) for suffix in suffixes)


def domain_modules(package_name: str) -> Tuple[str, ...]:
    return _qualify(package_name, DOMAIN_SUFFIXES)


def catalog_modules(package_name: str) -> Tuple[str, ...]:
    return _qualify(package_name, CATALOG_SUFFIXES)


def pure_modules(package_name: str) -> Tuple[str, ...]:
    """Domain and catalog modules: side-effect free, dependencies downward only."""
    return domain_modules(package_name) + catalog_modules(package_name)


def ui_entry_modules(package_name: str) -> Tuple[str, ...]:
    return _qualify(package_name, UI_ENTRY_SUFFIXES)

# Third-party imports the production runtime is allowed to reference. AuraScan's
# runtime dependency list is empty; only optional extras may appear, and each
# must be guarded by a fallback so an absent extra degrades gracefully.
ALLOWED_EXTERNAL_IMPORTS = frozenset(
    {
        "PyQt6",
        "PySide6",
        "tomli",
        "compression",  # stdlib zstd module on Python 3.14+, imported defensively
    }
)

# Libraries that belong to model research or training and must never be
# reachable from production code or from the shipped wheel.
FORBIDDEN_RESEARCH_IMPORTS = frozenset(
    {
        "torch",
        "transformers",
        "peft",
        "bitsandbytes",
        "datasets",
        "safetensors",
        "accelerate",
        "sentencepiece",
        "tokenizers",
        "trl",
        "vllm",
        "llama_cpp",
        "numpy",
        "pandas",
    }
)

# Import roots that are research tooling rather than production runtime.
RESEARCH_IMPORT_ROOTS = (
    "tools",
    "security_data",
    "model_lab",
    "aurascan_model_lab",
)

CAPABILITY_PREFIXES: Dict[str, Tuple[str, ...]] = {
    "process": (
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "subprocess",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnvp",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.fork",
        "os.forkpty",
        "os.startfile",
        "pty.spawn",
    ),
    "network": (
        "socket.socket",
        "socket.create_connection",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.socketpair",
        "urllib.request.urlopen",
        "urllib.request.Request",
        "urllib.request.build_opener",
        "urllib.request",
        "urlopen",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "http.client",
        "ftplib.FTP",
        "smtplib.SMTP",
        "telnetlib.Telnet",
        "socketserver.TCPServer",
        "ssl.SSLContext",
        "ssl.create_default_context",
        "ssl.wrap_socket",
    ),
    "fs_read": (
        "os.listdir",
        "os.scandir",
        "os.walk",
        "os.stat",
        "os.lstat",
        "os.readlink",
        "os.access",
        "os.getcwd",
        "os.read",
        "os.pread",
        "os.path.exists",
        "os.path.isfile",
        "os.path.isdir",
        "os.path.islink",
        "os.path.ismount",
        "os.path.getsize",
        "os.path.getmtime",
        "os.path.getatime",
        "os.path.realpath",
        "os.path.abspath",
        "os.path.expanduser",
        "os.path.samefile",
        "shutil.disk_usage",
        "shutil.which",
        "tempfile.gettempdir",
        "glob.glob",
        "glob.iglob",
        "fnmatch.filter",
    ),
    "fs_write": (
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "os.mkdir",
        "os.makedirs",
        "os.rmdir",
        "os.removedirs",
        "os.chmod",
        "os.fchmod",
        "os.chown",
        "os.lchown",
        "os.utime",
        "os.symlink",
        "os.link",
        "os.truncate",
        "os.write",
        "os.pwrite",
        "os.fsync",
        "os.mknod",
        "os.setsid",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copymode",
        "shutil.copystat",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
        "shutil.chown",
        "shutil.make_archive",
        "shutil.unpack_archive",
        "tempfile.mkstemp",
        "tempfile.mkdtemp",
        "tempfile.NamedTemporaryFile",
        "tempfile.TemporaryDirectory",
        "pathlib.Path.write_text",
        "pathlib.Path.write_bytes",
        "pathlib.Path.mkdir",
        "pathlib.Path.touch",
        "pathlib.Path.unlink",
        "pathlib.Path.rmdir",
        "pathlib.Path.rename",
        "pathlib.Path.replace",
        "pathlib.Path.chmod",
        "pathlib.Path.symlink_to",
        "pathlib.Path.hardlink_to",
    ),
    "privilege": (
        "os.setuid",
        "os.seteuid",
        "os.setreuid",
        "os.setresuid",
        "os.setgid",
        "os.setegid",
        "os.setregid",
        "os.setresgid",
        "os.setgroups",
        "os.initgroups",
        "os.chroot",
        "os.setns",
        "pwd.getpwnam",
        "pwd.getpwuid",
        "grp.getgrnam",
        "grp.getgrgid",
    ),
    "sqlite": (
        "sqlite3.connect",
        "sqlite3",
    ),
    "serialization": (
        "json.dump",
        "json.dumps",
        "json.load",
        "json.loads",
        "pickle.dump",
        "pickle.dumps",
        "pickle.load",
        "pickle.loads",
        "marshal.dump",
        "marshal.load",
        "configparser",
        "tomllib.load",
        "tomli.load",
    ),
    "archive": (
        "tarfile.open",
        "tarfile.TarFile",
        "zipfile.ZipFile",
        "zipfile.is_zipfile",
        "lzma.open",
        "bz2.open",
        "zlib.decompress",
    ),
}

# Resolved-name prefixes that would be ambiguous on their own; ``sqlite3`` and
# ``configparser`` above are bare-module tags used only for the survey.
_FILE_OBJECT_OPEN = "open"

# Attribute-name fallback for receivers that cannot be resolved statically
# (``path.write_text(...)`` where ``path`` is a local variable). The names are
# deliberately distinctive; common names such as ``write`` and ``read`` are
# omitted because ``open()`` already covers file objects.
ATTRIBUTE_FALLBACK: Dict[str, str] = {
    "write_text": "fs_write",
    "write_bytes": "fs_write",
    "mkdir": "fs_write",
    "touch": "fs_write",
    "unlink": "fs_write",
    "rmdir": "fs_write",
    "rename": "fs_write",
    "symlink_to": "fs_write",
    "hardlink_to": "fs_write",
    "chmod": "fs_write",
    "read_text": "fs_read",
    "read_bytes": "fs_read",
    "iterdir": "fs_read",
    "rglob": "fs_read",
    "is_file": "fs_read",
    "is_dir": "fs_read",
    "is_symlink": "fs_read",
    "readlink": "fs_read",
    "samefile": "fs_read",
    "is_mount": "fs_read",
}

OPEN_WRITE_MODE_CHARACTERS = frozenset("wax+")

# Concern tags: coarse descriptions of the kind of responsibility a module
# carries. They are used for reporting and for the advisory budget only.
# Concern tags describe the kind of responsibility a module carries. They drive
# the hotspot ranking and the advisory budget only; no invariant depends on them.
#
# ``policy`` and ``presentation`` are matched against distinctive symbols the
# module actually references. The remaining tags come from imports, measured
# capabilities and module path, which are far less ambiguous than scanning for
# ordinary words such as "state" or "cache".
POLICY_SYMBOLS: Tuple[str, ...] = (
    "Severity",
    "Confidence",
    "EvidenceQuality",
    "Finding",
    "rule_metadata",
    "presenter",
    "RiskLevel",
)
PRESENTATION_SYMBOLS: Tuple[str, ...] = (
    "print",
    "input",
    "ArgumentParser",
)
PARSER_MODULES: Tuple[str, ...] = (
    "ast",
    "tarfile",
    "zipfile",
    "configparser",
    "csv",
    "shlex",
    "lzma",
    "bz2",
    "tomllib",
    "tomli",
    "email",
)
AI_MODULES: Tuple[str, ...] = (
    "ai_provider",
    "ai_static",
    "context_provider",
)
TRAY_MODULES: Tuple[str, ...] = ("PyQt6", "PySide6")

# Concern tags derived from measured facts rather than symbol names.
FAN_OUT_ORCHESTRATION_THRESHOLD = 8

RISK_PATTERNS: Dict[str, str] = {
    "shell-true": "subprocess invoked with shell=True (shell interpretation of untrusted data)",
    "os-system": "os.system/os.popen (implicit shell)",
    "dynamic-eval": "eval/exec/compile/marshal/pickle of dynamic data",
    "tls-verify-disabled": "TLS certificate or hostname verification disabled",
    "insecure-mktemp": "tempfile.mktemp (race-prone temporary path)",
}

RUNTIME_EXCEPTION_IDS = {
    "shell-true",
    "os-system",
    "dynamic-eval",
    "tls-verify-disabled",
    "insecure-mktemp",
}

# Modules allowed to perform a capability that is otherwise forbidden for their
# layer. Every entry needs a documented reason. The keys are repository-relative
# paths, so the allowlist applies to the AuraScan package itself.
#
# INV-001 is currently empty on purpose: every analyzer delegates native tool
# execution to the trusted-tools adapter instead of running a process itself.
INVARIANT_ALLOWLIST: Dict[str, Dict[str, str]] = {
    "INV-001": {},
    "INV-002": {},    "INV-003": {},
    "INV-004": {},
    "INV-005": {},
    "INV-006": {},
    "INV-007": {},
    "INV-008": {},
    "INV-009": {},
    "INV-010": {},
    "INV-011": {},
    "INV-012": {},
}

RULE_ID_PATTERN = r"^[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+$"

# Advisory module-responsibility budget. Exceeding it prints a warning; it never
# changes the exit status and never fails a build.
BUDGET_MAX_CAPABILITIES = 5
BUDGET_MAX_CONCERNS = 5
BUDGET_MAX_LOC = 2500


class AuditError(Exception):
    """Raised when the audit cannot read its inputs."""


@dataclass
class Evidence:
    category: str
    symbol: str
    line: int


@dataclass
class RiskHit:
    pattern_id: str
    symbol: str
    line: int


@dataclass
class ModuleInfo:
    name: str
    path: str
    loc: int
    code_lines: int
    public_symbols: List[str]
    internal_imports: List[str] = field(default_factory=list)
    external_imports: List[str] = field(default_factory=list)
    capabilities: Dict[str, List[str]] = field(default_factory=dict)
    concerns: List[str] = field(default_factory=list)
    risk_patterns: List[RiskHit] = field(default_factory=list)
    layer: str = "unclassified"
    imports_by: List[str] = field(default_factory=list)
    rule_id_literals: int = 0

    @property
    def fan_out(self) -> int:
        return len(self.internal_imports)

    @property
    def fan_in(self) -> int:
        return len(self.imports_by)

    def hotspot_score(self) -> int:
        """Heuristic ranking key; every component is reported separately.

        ``3 * capabilities + 2 * concerns`` weights mixed responsibility highest,
        then adds small bonuses for very large or heavily depended-on modules.
        The point is to surface candidates for human review, not to rank quality.
        """
        score = 3 * len(self.capabilities) + 2 * len(self.concerns)
        if self.loc >= 2000:
            score += 1
        if self.fan_in >= 15:
            score += 1
        return score

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "layer": self.layer,
            "loc": self.loc,
            "code_lines": self.code_lines,
            "public_symbols": self.public_symbols,
            "internal_imports": self.internal_imports,
            "external_imports": self.external_imports,
            "imports_by": self.imports_by,
            "fan_in": self.fan_in,
            "fan_out": self.fan_out,
            "capabilities": self.capabilities,
            "concerns": self.concerns,
            "risk_patterns": [
                {"pattern_id": hit.pattern_id, "symbol": hit.symbol, "line": hit.line}
                for hit in self.risk_patterns
            ],
            "hotspot_score": self.hotspot_score(),
            "rule_id_literals": self.rule_id_literals,
        }


@dataclass
class Violation:
    invariant_id: str
    title: str
    module: str
    detail: str
    line: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "invariant_id": self.invariant_id,
            "title": self.title,
            "module": self.module,
            "detail": self.detail,
            "line": self.line,
        }


@dataclass
class Invariant:
    invariant_id: str
    title: str
    rationale: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "invariant_id": self.invariant_id,
            "title": self.title,
            "rationale": self.rationale,
            "allowlist": INVARIANT_ALLOWLIST.get(self.invariant_id, {}),
        }


INVARIANTS: Tuple[Invariant, ...] = (
    Invariant(
        "INV-001",
        "static analyzers must not execute processes",
        "Analysis inspects untrusted package text; it must not gain process "
        "execution. Analyzers obtain native-tool results through the "
        "trusted-tools adapter (aurascan/core/trusted_tools.py), so the "
        "execution boundary stays in one reviewable place.",
    ),
    Invariant(
        "INV-002",
        "production code must not use shell=True",
        "A shell would interpret untrusted package or agent text. Every "
        "subprocess call must pass an explicit argument vector.",
    ),
    Invariant(
        "INV-003",
        "production code must not import training or model-research libraries",
        "Model-lab and training dependencies belong to research tooling and "
        "must never enter the shipped wheel or the runtime import graph.",
    ),
    Invariant(
        "INV-004",
        "production code must not import research tooling",
        "The production package must not depend on tools/, security-data or "
        "model-lab modules; the dependency runs the other way only.",
    ),
    Invariant(
        "INV-005",
        "production runtime must stay standard library plus declared extras",
        "AuraScan has no required runtime dependencies. Only optional extras "
        "with graceful fallbacks may be imported.",
    ),
    Invariant(
        "INV-006",
        "domain and policy modules must not depend on AI provider modules",
        "Deterministic policy is authoritative. AI is advisory, so policy code "
        "must not acquire a dependency on the provider transport.",
    ),
    Invariant(
        "INV-007",
        "core application code must not import presentation modules",
        "CLI, tray, wizard and entry points depend downward on core. The "
        "reverse edge would make policy and analysis depend on the UI.",
    ),
    Invariant(
        "INV-008",
        "production code must not evaluate or unpickle dynamic data",
        "eval/exec/compile/marshal/pickle on untrusted content is code "
        "execution. Static analysis must never deserialize candidate bytes.",
    ),
    Invariant(
        "INV-009",
        "production code must not disable TLS verification",
        "Network acquisition must verify the peer; a disabled check would "
        "silently weaken intelligence and advisory integrity.",
    ),
    Invariant(
        "INV-010",
        "domain modules must remain free of side effects",
        "Evidence models, severity metadata and text safety are pure data and "
        "pure functions so they stay trivially reviewable and testable.",
    ),
    Invariant(
        "INV-011",
        "UI entry points must not contain rule IDs",
        "Rule identifiers are policy output. A CLI, tray or wizard renders the "
        "findings it is given; it must not decide which rules exist.",
    ),
    Invariant(
        "INV-012",
        "domain and catalog modules must depend only on domain and catalog",
        "Evidence models, severity metadata and explanation templates sit at "
        "the bottom of the dependency graph. An upward edge (for example a "
        "model importing a renderer) is what created the models<->presenter "
        "cycle reported by this audit.",
    ),
)

INVARIANT_BY_ID: Dict[str, Invariant] = {
    invariant.invariant_id: invariant for invariant in INVARIANTS
}


class NameResolver(ast.NodeVisitor):
    """Collect import aliases so call sites can be resolved to dotted names."""

    def __init__(self) -> None:
        self.aliases: Dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".")[0]
                self.aliases[root] = root
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            if module:
                self.aliases[local] = "{0}.{1}".format(module, alias.name)
            else:
                self.aliases[local] = alias.name
        self.generic_visit(node)

    def resolve(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            if base is None:
                return None
            return "{0}.{1}".format(base, node.attr)
        if isinstance(node, ast.Call):
            return self.resolve(node.func)
        return None


def _literal_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_bool(node: Optional[ast.AST]) -> Optional[bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _capability_index() -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    for category, prefixes in CAPABILITY_PREFIXES.items():
        for prefix in prefixes:
            entries.append((prefix, category))
    entries.sort(key=lambda item: len(item[0]), reverse=True)
    return entries


CAPABILITY_INDEX = _capability_index()


def _match_prefix(dotted: str) -> Optional[Tuple[str, str]]:
    for prefix, category in CAPABILITY_INDEX:
        if dotted == prefix or dotted.startswith(prefix + "."):
            return prefix, category
    return None


class ModuleVisitor(ast.NodeVisitor):
    """Extract imports, capabilities, concerns and risk patterns from one module."""

    def __init__(
        self,
        module_name: str,
        known_modules: Set[str],
        known_rule_ids: Optional[Set[str]] = None,
    ) -> None:
        self.module_name = module_name
        self.known_modules = known_modules
        self.known_rule_ids = known_rule_ids or set()
        self.resolver = NameResolver()
        self.internal_imports: Set[str] = set()
        self.external_imports: Set[str] = set()
        self.public_symbols: Set[str] = set()
        self.rule_id_literals = 0
        self._evidence: Dict[str, Set[str]] = {}
        self._risk_hits: List[RiskHit] = []
        self._defined_names: Set[str] = set()
        self._used_names: Set[str] = set()

    # -- imports ---------------------------------------------------------- #
    def visit_Import(self, node: ast.Import) -> None:
        self.resolver.visit(node)
        for alias in node.names:
            self._record_import(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.resolver.visit(node)
        module = self._absolute_module(node)
        if module is None:
            return
        for alias in node.names:
            candidate = "{0}.{1}".format(module, alias.name)
            if candidate in self.known_modules:
                self._record_import(candidate)
            else:
                self._record_import(module)
        self.generic_visit(node)

    def _absolute_module(self, node: ast.ImportFrom) -> Optional[str]:
        if node.level == 0:
            return node.module
        # ``__init__.py`` files are named after their package, so a module's
        # containing package is always its dotted name without the final part.
        package = self.module_name.split(".")[:-1]
        if node.level > len(package):
            return None
        base = package[: len(package) - (node.level - 1)]
        if not base:
            return None
        return ".".join(base + ([node.module] if node.module else []))

    def _record_import(self, dotted: str) -> None:
        resolved = self._longest_known_module(dotted)
        if resolved is not None:
            if resolved != self.module_name:
                self.internal_imports.add(resolved)
            return
        self.external_imports.add(dotted.split(".")[0])

    def _longest_known_module(self, dotted: str) -> Optional[str]:
        parts = dotted.split(".")
        for size in range(len(parts), 0, -1):
            candidate = ".".join(parts[:size])
            if candidate in self.known_modules:
                return candidate
        return None

    # -- symbols ---------------------------------------------------------- #
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record_definition(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record_definition(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._record_definition(node.name)
        self.generic_visit(node)

    def _record_definition(self, name: str) -> None:
        self._defined_names.add(name)
        if not name.startswith("_"):
            self.public_symbols.add(name)

    # -- calls ------------------------------------------------------------ #
    def visit_Call(self, node: ast.Call) -> None:
        resolved = self.resolver.resolve(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
        for category, symbol in self._classify_call(node, resolved, attr):
            self._evidence.setdefault(category, set()).add(symbol)
        for hit in self._risk_hits_for(node, resolved, attr):
            self._risk_hits.append(hit)
        self.generic_visit(node)

    def _classify_call(
        self, node: ast.Call, resolved: Optional[str], attr: Optional[str]
    ) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        if resolved:
            match = _match_prefix(resolved)
            if match is not None:
                prefix, category = match
                if category == "sqlite" and prefix == "sqlite3":
                    results.append(("sqlite", "sqlite3"))
                elif prefix == "subprocess":
                    results.append(("process", "subprocess"))
                else:
                    results.append((category, prefix))
                return results
            if resolved == _FILE_OBJECT_OPEN:
                mode = self._open_mode(node)
                if mode is not None and any(ch in OPEN_WRITE_MODE_CHARACTERS for ch in mode):
                    results.append(("fs_write", "open"))
                else:
                    results.append(("fs_read", "open"))
                return results
        if attr and attr in ATTRIBUTE_FALLBACK:
            results.append((ATTRIBUTE_FALLBACK[attr], "*." + attr))
        return results

    @staticmethod
    def _literal_first_argument(node: ast.Call) -> bool:
        """True when the first positional argument is a plain string literal.

        ``__import__("urllib.request", ...)`` and ``importlib.import_module("x")``
        are lazy imports of a fixed module, not dynamic evaluation of data. Only
        a computed argument is treated as dynamic code loading.
        """
        if not node.args:
            return False
        return _literal_str(node.args[0]) is not None

    @staticmethod
    def _open_mode(node: ast.Call) -> Optional[str]:
        if len(node.args) > 1:
            mode = _literal_str(node.args[1])
            if mode is not None:
                return mode
        for keyword in node.keywords:
            if keyword.arg == "mode":
                return _literal_str(keyword.value)
        return None

    def _risk_hits_for(
        self, node: ast.Call, resolved: Optional[str], attr: Optional[str]
    ) -> List[RiskHit]:
        hits: List[RiskHit] = []
        if resolved:
            if resolved.startswith("subprocess.") or resolved == "subprocess":
                for keyword in node.keywords:
                    if keyword.arg == "shell" and _literal_bool(keyword.value) is True:
                        hits.append(RiskHit("shell-true", resolved, node.lineno))
            if resolved in ("os.system", "os.popen"):
                hits.append(RiskHit("os-system", resolved, node.lineno))
            if resolved in (
                "eval",
                "exec",
                "compile",
                "__import__",
                "importlib.import_module",
                "marshal.load",
                "marshal.loads",
                "pickle.load",
                "pickle.loads",
            ):
                if not self._literal_first_argument(node):
                    hits.append(RiskHit("dynamic-eval", resolved, node.lineno))
            if resolved == "tempfile.mktemp":
                hits.append(RiskHit("insecure-mktemp", resolved, node.lineno))
            if resolved == "ssl._create_unverified_context":
                hits.append(RiskHit("tls-verify-disabled", resolved, node.lineno))
        for keyword in node.keywords:
            if keyword.arg == "verify" and _literal_bool(keyword.value) is False:
                hits.append(RiskHit("tls-verify-disabled", "verify=False", node.lineno))
            if keyword.arg == "check_hostname" and _literal_bool(keyword.value) is False:
                hits.append(RiskHit("tls-verify-disabled", "check_hostname=False", node.lineno))
            if keyword.arg == "cert_reqs" and _literal_bool(keyword.value) is not None:
                if _literal_bool(keyword.value) is False:
                    hits.append(RiskHit("tls-verify-disabled", "cert_reqs", node.lineno))
        return hits

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node.value in self.known_rule_ids:
            self.rule_id_literals += 1
        self.generic_visit(node)

    # -- results ---------------------------------------------------------- #
    def collect_used_names(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                self._used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                self._used_names.add(node.attr)

    def _references(self, symbol: str) -> bool:
        if symbol in self._used_names or symbol in self._defined_names:
            return True
        for alias in self.resolver.aliases.values():
            if alias == symbol or alias.endswith("." + symbol):
                return True
        for imported in self.internal_imports | self.external_imports:
            if imported.split(".")[-1] == symbol:
                return True
        return False

    def _imports_module(self, stem: str) -> bool:
        for imported in self.internal_imports:
            if imported.split(".")[-1] == stem:
                return True
        return stem in self.external_imports

    @property
    def capabilities(self) -> Dict[str, List[str]]:
        return {
            category: sorted(symbols)
            for category, symbols in sorted(self._evidence.items())
        }

    @property
    def risk_hits(self) -> List[RiskHit]:
        return self._risk_hits

    def concerns(self, fan_out: int) -> List[str]:
        found: Set[str] = set()
        if any(self._references(symbol) for symbol in POLICY_SYMBOLS):
            found.add("policy")
        if any(self._references(symbol) for symbol in PRESENTATION_SYMBOLS):
            found.add("presentation")
        if any(self._imports_module(stem) for stem in PARSER_MODULES):
            found.add("parsing")
        if any(self._imports_module(stem) for stem in AI_MODULES):
            found.add("ai")
        if any(self._imports_module(stem) for stem in TRAY_MODULES):
            found.add("tray-toolkit")
        if "sqlite" in self._evidence or self._imports_module("cache"):
            found.add("persistence")
        if self.module_name.split(".")[-1].startswith("recovery"):
            found.add("recovery")
        if "process" in self._evidence:
            found.add("process-boundary")
        if "network" in self._evidence:
            found.add("network-boundary")
        if "fs_write" in self._evidence:
            found.add("mutation")
        if "privilege" in self._evidence:
            found.add("privilege-boundary")
        if fan_out >= FAN_OUT_ORCHESTRATION_THRESHOLD:
            found.add("orchestration")
        return sorted(found)


def assign_layer(module_name: str, relative_path: str) -> str:
    """Assign a reporting layer from repository structure.

    Layers describe where a module sits in the dependency story. They are used
    for documentation and for a few narrow invariants, not for blanket
    enforcement of a full layered architecture.
    """
    if relative_path.startswith("analyzers/"):
        return "analysis"
    if relative_path.startswith("assets/"):
        return "assets"
    if relative_path.startswith("core/"):
        stem = relative_path.split("/")[-1]
        name = stem[:-3] if stem.endswith(".py") else stem
        if name in ("models", "risk", "text_safety", "update_policy"):
            return "domain"
        if name in ("rule_metadata", "presenter"):
            return "catalog"
        if name in (
            "updater_tray",
            "intelligence_tray",
            "instruction_cli",
            "intelligence_cli",
            "recovery_cli",
        ):
            return "presentation"
        if name in (
            "trusted_tools",
            "trusted_executable",
            "source_acquisition",
            "intelligence_transport",
            "archive",
            "package_archive",
            "cache",
            "local_package_db",
            "intelligence_crypto",
            "ai_provider",
            "recovery_network",
            "compatibility",
        ):
            return "adapters"
        if name.startswith("recovery"):
            return "recovery"
        return "application"
    if relative_path in ("cli.py", "setup_wizard.py", "makepkg_wrapper.py", "__main__.py"):
        return "presentation"
    if relative_path == "__init__.py":
        return "package"
    return "unclassified"


def discover_modules(package_root: Path, package_name: str) -> Dict[str, Path]:
    modules: Dict[str, Path] = {}
    for path in sorted(package_root.rglob("*.py")):
        relative = path.relative_to(package_root).as_posix()
        if relative.endswith("__init__.py"):
            suffix = relative[: -len("__init__.py")].strip("/")
            parts = [part for part in suffix.split("/") if part]
            module = ".".join([package_name] + parts)
        else:
            parts = relative[:-3].split("/")
            module = ".".join([package_name] + parts)
        modules[module] = path
    return modules


def load_known_rule_ids(rule_metadata_path: Path) -> Set[str]:
    """Read declared rule IDs straight from the rule metadata module.

    Parsing (never importing) the catalog keeps this tool independent while
    still making INV-011 precise: a string such as ``SHA-256`` is not mistaken
    for a rule identifier.
    """
    if not rule_metadata_path.is_file():
        return set()
    try:
        tree = ast.parse(rule_metadata_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    found: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "RULE_METADATA":
                    if isinstance(node.value, ast.Dict):
                        for key in node.value.keys:
                            value = _literal_str(key)
                            if value and re.match(RULE_ID_PATTERN, value):
                                found.add(value)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "RuleMetadata" and node.args:
                value = _literal_str(node.args[0])
                if value and re.match(RULE_ID_PATTERN, value):
                    found.add(value)
    return found


def build_audit(
    package_root: Path,
    package_name: str,
    rule_metadata_path: Optional[Path] = None,
) -> List[ModuleInfo]:
    modules = discover_modules(package_root, package_name)
    if not modules:
        raise AuditError("no Python modules found under {0}".format(package_root))
    known = set(modules)
    known_rule_ids = (
        load_known_rule_ids(rule_metadata_path) if rule_metadata_path is not None else set()
    )
    infos: List[ModuleInfo] = []
    for module_name, path in sorted(modules.items()):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            raise AuditError("cannot read {0}: {1}".format(path, error))
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as error:
            raise AuditError("cannot parse {0}: {1}".format(path, error))
        visitor = ModuleVisitor(module_name, known, known_rule_ids)
        visitor.visit(tree)
        visitor.collect_used_names(tree)
        lines = source.splitlines()
        code_lines = sum(
            1
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        )
        relative = path.relative_to(package_root).as_posix()
        info = ModuleInfo(
            name=module_name,
            path="{0}/{1}".format(package_name, relative),
            loc=len(lines),
            code_lines=code_lines,
            public_symbols=sorted(visitor.public_symbols),
            internal_imports=sorted(visitor.internal_imports),
            external_imports=sorted(visitor.external_imports),
            capabilities=visitor.capabilities,
            risk_patterns=visitor.risk_hits,
            layer=assign_layer(module_name, relative),
            rule_id_literals=visitor.rule_id_literals,
        )
        info.concerns = visitor.concerns(info.fan_out)
        infos.append(info)

    by_name = {info.name: info for info in infos}
    for info in infos:
        for imported in info.internal_imports:
            target = by_name.get(imported)
            if target is not None:
                target.imports_by.append(info.name)
    for info in infos:
        info.imports_by.sort()
    return infos


def find_cycles(infos: Sequence[ModuleInfo]) -> List[List[str]]:
    """Return strongly connected components with more than one module."""
    graph = {info.name: [dep for dep in info.internal_imports] for info in infos}
    index_counter = [0]
    stack: List[str] = []
    lowlink: Dict[str, int] = {}
    index: Dict[str, int] = {}
    on_stack: Dict[str, bool] = {}
    components: List[List[str]] = []

    def strongconnect(node: str) -> None:
        index[node] = index_counter[0]
        lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack[node] = True
        for successor in graph.get(node, []):
            if successor not in graph:
                continue
            if successor not in index:
                strongconnect(successor)
                lowlink[node] = min(lowlink[node], lowlink[successor])
            elif on_stack.get(successor):
                lowlink[node] = min(lowlink[node], index[successor])
        if lowlink[node] == index[node]:
            component: List[str] = []
            while True:
                successor = stack.pop()
                on_stack[successor] = False
                component.append(successor)
                if successor == node:
                    break
            if len(component) > 1:
                components.append(sorted(component))

    for node in sorted(graph):
        if node not in index:
            strongconnect(node)
    return sorted(components)


def _violation(invariant_id: str, module: str, detail: str, line: int = 0) -> Violation:
    return Violation(
        invariant_id,
        INVARIANT_BY_ID[invariant_id].title,
        module,
        detail,
        line,
    )


def evaluate_invariants(infos: Sequence[ModuleInfo], package_name: str) -> List[Violation]:
    violations: List[Violation] = []
    pure = pure_modules(package_name)
    ui_entries = ui_entry_modules(package_name)
    for info in infos:
        allow = INVARIANT_ALLOWLIST
        if info.layer == "analysis" and "process" in info.capabilities:
            if info.path not in allow["INV-001"]:
                violations.append(
                    _violation(
                        "INV-001",
                        info.path,
                        "analysis module declares process capability: {0}".format(
                            ", ".join(info.capabilities["process"])
                        ),
                    )
                )

        for hit in info.risk_patterns:
            if hit.pattern_id == "shell-true" and info.path not in allow["INV-002"]:
                violations.append(
                    _violation("INV-002", info.path, "shell=True call", hit.line)
                )
            if hit.pattern_id == "dynamic-eval" and info.path not in allow["INV-008"]:
                violations.append(
                    _violation(
                        "INV-008",
                        info.path,
                        "dynamic evaluation via {0}".format(hit.symbol),
                        hit.line,
                    )
                )
            if hit.pattern_id == "tls-verify-disabled" and info.path not in allow["INV-009"]:
                violations.append(
                    _violation(
                        "INV-009",
                        info.path,
                        "disabled TLS verification via {0}".format(hit.symbol),
                        hit.line,
                    )
                )
            if hit.pattern_id == "os-system" and info.path not in allow["INV-002"]:
                violations.append(
                    _violation(
                        "INV-002",
                        info.path,
                        "implicit shell via {0}".format(hit.symbol),
                        hit.line,
                    )
                )

        for external in info.external_imports:
            if external in FORBIDDEN_RESEARCH_IMPORTS:
                violations.append(
                    _violation(
                        "INV-003",
                        info.path,
                        "imports research/training library {0}".format(external),
                    )
                )
                continue
            if external not in ALLOWED_EXTERNAL_IMPORTS and not _is_stdlib(external):
                violations.append(
                    _violation(
                        "INV-005",
                        info.path,
                        "imports undeclared third-party module {0}".format(external),
                    )
                )

        for imported in info.internal_imports:
            if imported.split(".")[0] in RESEARCH_IMPORT_ROOTS:
                violations.append(
                    _violation(
                        "INV-004",
                        info.path,
                        "imports research tooling {0}".format(imported),
                    )
                )

        if info.name in pure:
            for imported in info.internal_imports:
                if imported.split(".")[-1] in ("ai_provider", "ai_static", "context_provider"):
                    violations.append(
                        _violation(
                            "INV-006",
                            info.path,
                            "domain/catalog module imports AI module {0}".format(imported),
                        )
                    )
            for category in ("process", "network", "fs_write", "privilege", "sqlite"):
                if category in info.capabilities:
                    violations.append(
                        _violation(
                            "INV-010",
                            info.path,
                            "domain/catalog module declares {0} capability: {1}".format(
                                category, ", ".join(info.capabilities[category])
                            ),
                        )
                    )
            for imported in info.internal_imports:
                if imported not in pure:
                    violations.append(
                        _violation(
                            "INV-012",
                            info.path,
                            "pure module depends upward on {0}".format(imported),
                        )
                    )

        if info.layer not in ("presentation", "unclassified"):
            for imported in info.internal_imports:
                if imported in ui_entries:
                    violations.append(
                        _violation(
                            "INV-007",
                            info.path,
                            "non-presentation module imports {0}".format(imported),
                        )
                    )

        if info.name in ui_entries and info.rule_id_literals:
            violations.append(
                _violation(
                    "INV-011",
                    info.path,
                    "UI entry point contains {0} rule-ID literal(s)".format(
                        info.rule_id_literals
                    ),
                )
            )
    return violations


def _is_stdlib(name: str) -> bool:
    """Best-effort standard-library check for Python 3.8 through 3.14.

    ``sys.stdlib_module_names`` exists from Python 3.10; older interpreters
    fall back to probing the running interpreter's standard-library directory.
    """
    known = getattr(sys, "stdlib_module_names", None)
    if known is not None:
        return name in known
    try:
        stdlib = Path(sysconfig.get_paths()["stdlib"])
    except (KeyError, OSError):
        return False
    return (stdlib / (name + ".py")).exists() or (stdlib / name / "__init__.py").exists()


def budget_warnings(infos: Sequence[ModuleInfo]) -> List[str]:
    warnings: List[str] = []
    for info in infos:
        reasons: List[str] = []
        if len(info.capabilities) > BUDGET_MAX_CAPABILITIES:
            reasons.append("{0} capability categories".format(len(info.capabilities)))
        if len(info.concerns) > BUDGET_MAX_CONCERNS:
            reasons.append("{0} concern tags".format(len(info.concerns)))
        if info.loc > BUDGET_MAX_LOC:
            reasons.append("{0} physical lines".format(info.loc))
        if reasons:
            warnings.append("{0}: {1}".format(info.path, ", ".join(reasons)))
    return sorted(warnings)


def render_text(audit: "AuditResult", top: int) -> str:
    lines: List[str] = []
    lines.append("AuraScan architecture audit")
    lines.append("=" * 26)
    lines.append("")
    lines.append("Modules: {0}".format(len(audit.modules)))
    lines.append("Total physical lines: {0}".format(sum(m.loc for m in audit.modules)))
    lines.append("")

    lines.append("Layers")
    lines.append("-" * 6)
    layer_counts: Dict[str, int] = {}
    for info in audit.modules:
        layer_counts[info.layer] = layer_counts.get(info.layer, 0) + 1
    for layer in sorted(layer_counts):
        lines.append("  {0:<14} {1:>3} module(s)".format(layer, layer_counts[layer]))
    lines.append("")

    lines.append("Capability distribution (module count per capability)")
    lines.append("-" * 50)
    capability_counts: Dict[str, List[str]] = {}
    for info in audit.modules:
        for category in info.capabilities:
            capability_counts.setdefault(category, []).append(info.path)
    for category in sorted(capability_counts):
        paths = capability_counts[category]
        lines.append("  {0:<16} {1:>3}".format(category, len(paths)))
    lines.append("")

    lines.append("Top {0} hotspots by mixed-responsibility heuristic".format(top))
    lines.append("-" * 60)
    lines.append(
        "  {0:<52} {1:>6} {2:>5} {3:>5} {4:>5} {5:>6}".format(
            "module", "loc", "caps", "conc", "fan", "score"
        )
    )
    for info in audit.hotspots[:top]:
        lines.append(
            "  {0:<52} {1:>6} {2:>5} {3:>5} {4:>5} {5:>6}".format(
                info.path,
                info.loc,
                len(info.capabilities),
                len(info.concerns),
                info.fan_in,
                info.hotspot_score(),
            )
        )
    lines.append("")

    lines.append("Most depended-on modules (fan-in)")
    lines.append("-" * 33)
    for info in sorted(audit.modules, key=lambda m: (-m.fan_in, m.path))[:top]:
        if info.fan_in:
            lines.append("  {0:>3}  {1}".format(info.fan_in, info.path))
    lines.append("")

    lines.append("Widest import fan-out")
    lines.append("-" * 20)
    for info in sorted(audit.modules, key=lambda m: (-m.fan_out, m.path))[:top]:
        lines.append("  {0:>3}  {1}".format(info.fan_out, info.path))
    lines.append("")

    lines.append("Import cycles (strongly connected components)")
    lines.append("-" * 46)
    if not audit.cycles:
        lines.append("  none")
    for component in audit.cycles:
        lines.append("  {0} modules:".format(len(component)))
        for name in component:
            lines.append("    - {0}".format(name))
    lines.append("")

    lines.append("Risk patterns")
    lines.append("-" * 13)
    any_hit = False
    for info in audit.modules:
        for hit in info.risk_patterns:
            any_hit = True
            lines.append(
                "  {0}:{1}: {2} ({3})".format(info.path, hit.line, hit.pattern_id, hit.symbol)
            )
    if not any_hit:
        lines.append("  none detected")
    lines.append("")

    lines.append("Architecture invariants")
    lines.append("-" * 23)
    by_id: Dict[str, List[Violation]] = {}
    for violation in audit.violations:
        by_id.setdefault(violation.invariant_id, []).append(violation)
    for invariant in INVARIANTS:
        found = by_id.get(invariant.invariant_id, [])
        status = "PASS" if not found else "FAIL ({0})".format(len(found))
        lines.append("  {0}  {1:<58} {2}".format(invariant.invariant_id, invariant.title, status))
        for violation in found:
            location = "{0}:{1}".format(violation.module, violation.line) if violation.line else violation.module
            lines.append("        {0} -- {1}".format(location, violation.detail))
    lines.append("")

    lines.append("Advisory responsibility budget")
    lines.append("-" * 30)
    if not audit.budget:
        lines.append("  no module exceeds the advisory budget")
    for warning in audit.budget:
        lines.append("  warn: {0}".format(warning))
    lines.append("")
    return "\n".join(lines)


def render_markdown(audit: "AuditResult", top: int) -> str:
    lines: List[str] = []
    lines.append("### Module inventory (generated)")
    lines.append("")
    lines.append(
        "Generated by `python tools/architecture_audit.py --format markdown`. "
        "Capabilities describe call sites and imports, not reachability."
    )
    lines.append("")
    lines.append("| Module | Layer | Lines | Capabilities | Concerns | Fan-in | Fan-out |")
    lines.append("| --- | --- | ---: | --- | --- | ---: | ---: |")
    for info in sorted(audit.modules, key=lambda m: m.path):
        capabilities = ", ".join(
            "{0}:{1}".format(category, len(symbols))
            for category, symbols in sorted(info.capabilities.items())
        )
        lines.append(
            "| `{0}` | {1} | {2} | {3} | {4} | {5} | {6} |".format(
                info.path,
                info.layer,
                info.loc,
                capabilities or "-",
                ", ".join(info.concerns) or "-",
                info.fan_in,
                info.fan_out,
            )
        )
    lines.append("")
    lines.append("### Hotspots (generated)")
    lines.append("")
    lines.append("| Module | Lines | Capabilities | Concerns | Fan-in | Score |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for info in audit.hotspots[:top]:
        lines.append(
            "| `{0}` | {1} | {2} | {3} | {4} | {5} |".format(
                info.path,
                info.loc,
                len(info.capabilities),
                len(info.concerns),
                info.fan_in,
                info.hotspot_score(),
            )
        )
    lines.append("")
    return "\n".join(lines)


@dataclass
class AuditResult:
    modules: List[ModuleInfo]
    cycles: List[List[str]]
    violations: List[Violation]
    budget: List[str]
    hotspots: List[ModuleInfo]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": "aurascan-architecture-audit/1.0",
            "module_count": len(self.modules),
            "loc_total": sum(info.loc for info in self.modules),
            "invariants": [invariant.to_dict() for invariant in INVARIANTS],
            "violations": [violation.to_dict() for violation in self.violations],
            "cycles": self.cycles,
            "budget_warnings": self.budget,
            "hotspots": [
                {"path": info.path, "score": info.hotspot_score(), "loc": info.loc}
                for info in self.hotspots
            ],
            "modules": [info.to_dict() for info in sorted(self.modules, key=lambda m: m.path)],
        }


def run_audit(
    package_root: Path,
    package_name: str,
    rule_metadata_path: Optional[Path] = None,
) -> AuditResult:
    modules = build_audit(package_root, package_name, rule_metadata_path)
    cycles = find_cycles(modules)
    violations = evaluate_invariants(modules, package_name)
    budget = budget_warnings(modules)
    hotspots = sorted(modules, key=lambda m: (-m.hotspot_score(), -m.loc, m.path))
    return AuditResult(
        modules=modules,
        cycles=cycles,
        violations=violations,
        budget=budget,
        hotspots=hotspots,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report AuraScan module responsibilities, coupling, capabilities, "
            "import cycles and architecture invariant results."
        )
    )
    parser.add_argument(
        "--package-root",
        default=str(DEFAULT_PACKAGE_ROOT),
        help="package directory to audit (default: aurascan/)",
    )
    parser.add_argument(
        "--package-name",
        default="aurascan",
        help="import package name for the audited directory (default: aurascan)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--rule-metadata",
        default=str(DEFAULT_PACKAGE_ROOT / "core" / "rule_metadata.py"),
        help="rule catalog parsed for INV-011 precision",
    )
    parser.add_argument("--top", type=int, default=20, help="rows in ranked tables (default: 20)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when a blocking architecture invariant fails",
    )
    args = parser.parse_args(argv)

    package_root = Path(args.package_root)
    if not package_root.is_absolute():
        package_root = (ROOT / package_root).resolve()
    if not package_root.is_dir():
        print("error: package root not found: {0}".format(package_root), file=sys.stderr)
        return 1

    rule_metadata = Path(args.rule_metadata)
    if not rule_metadata.is_absolute():
        rule_metadata = (ROOT / rule_metadata).resolve()

    try:
        result = run_audit(package_root, args.package_name, rule_metadata)
    except AuditError as error:
        print("error: {0}".format(error), file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif args.format == "markdown":
        print(render_markdown(result, args.top))
    else:
        print(render_text(result, args.top))

    if args.strict and result.violations:
        print(
            "strict: {0} architecture invariant violation(s)".format(len(result.violations)),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
