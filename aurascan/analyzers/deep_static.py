import hashlib
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Iterable, List, Optional

from aurascan.analyzers.base import BaseAnalyzer
from aurascan.analyzers.clamav import ClamAVAnalyzer
from aurascan.analyzers.editor_tasks import editor_task_findings
from aurascan.analyzers.npm_metadata import (
    MetadataIncomplete, inspect_npm_metadata, strict_json_object,
)
from aurascan.analyzers.npm_supply_chain import (
    analyze_npm_install_commands, inspect_npm_campaign_metadata,
    known_payload_digest_findings, known_payload_findings,
)
from aurascan.analyzers.npm_lifecycle import inspect_npm_lifecycle
from aurascan.analyzers.python_bytecode import (
    PYTHON_PRECOMPILED_CANDIDATE,
    classify_python_precompiled, is_python_precompiled_path,
    python_precompiled_findings,
)
from aurascan.analyzers.python_bytecode_execution import (
    analyze_precompiled_execution, is_precompiled_control_script,
)
from aurascan.analyzers.remote_access import find_remote_access_backdoor_signals
from aurascan.analyzers.remote_stage import (
    analyze_carrier_execution,
    analyze_remote_stage_execution,
)
from aurascan.core.archive import SafeArchiveExtractor
from aurascan.core.repository_provenance import _classify_artifact, is_editor_tasks_path
from aurascan.core.models import (
    AnalysisResult,
    Confidence,
    EvidenceQuality,
    Finding,
    Phase,
    Severity,
    Source,
)
from aurascan.core.source_acquisition import SourceFetcher, SourceKind, SourceParser


INTERESTING_NAMES = {
    "Makefile", "CMakeLists.txt", "meson.build", "configure", "autogen.sh",
    "setup.py", "pyproject.toml", "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml", "Cargo.toml", "Cargo.lock", "go.mod",
    "go.sum", "composer.json", "Gemfile", "hyprland-fixes",
    "hyprland-fixes-permissions", "hyprland-fixes-post-install",
    "hyprland-windowrule-and-keybind-fixes",
}
TEXT_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".service", ".timer", ".cron"}
VENDORED_DIRS = {"node_modules", "vendor", "third_party", "deps"}
NESTED_ARCHIVE_SUFFIXES = (
    ".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.zst", ".zip",
    ".tar.bz2", ".tbz2", ".tar.lz", ".7z", ".rar",
)
_ARCHIVE_KINDS = frozenset({"zip", "gzip", "bzip2", "xz", "zstd", "7z", "rar", "ar", "tar"})


class DeepStaticAnalyzer(BaseAnalyzer):
    def __init__(
        self,
        extractor: Optional[SafeArchiveExtractor] = None,
        clamav: Optional[ClamAVAnalyzer] = None,
        source_parser: Optional[SourceParser] = None,
        source_fetcher: Optional[SourceFetcher] = None,
        max_file_size: int = 1024 * 1024,
        max_tree_entries: int = 20000,
        max_candidates: int = 5000,
        max_hash_file_size: int = 64 * 1024 * 1024,
        max_total_file_bytes: int = 256 * 1024 * 1024,
        intelligence_snapshot=None,
    ):
        from aurascan.core.intelligence import bundled_snapshot
        self.intelligence_snapshot = (intelligence_snapshot if intelligence_snapshot is not None
                                      else bundled_snapshot())
        self.extractor = extractor or SafeArchiveExtractor()
        self.clamav = clamav or ClamAVAnalyzer()
        self.source_parser = source_parser or SourceParser()
        self.source_fetcher = source_fetcher or SourceFetcher()
        self.max_file_size = max_file_size
        self.max_tree_entries = max(1, max_tree_entries)
        self.max_candidates = max(1, max_candidates)
        self.max_hash_file_size = max(1, max_hash_file_size)
        self.max_total_file_bytes = max(1, max_total_file_bytes)
        self.last_source_acquisition = []
        self._tree_scan_incomplete = False
        self._last_read_bytes = 0
        self._last_read_prefix = b""

    def analyze_pkgbuild(self, pkgbuild_path: str, content: str) -> AnalysisResult:
        findings: List[Finding] = []
        self.last_source_acquisition = []
        refs, parser_findings = self.source_parser.parse(pkgbuild_path, content)
        findings.extend(parser_findings)
        pkg_dir = Path(pkgbuild_path).resolve().parent

        if not refs and not parser_findings:
            return AnalysisResult(True, "Deep static scan found no declared sources", findings)

        temp_dirs: List[Path] = []
        try:
            acquisitions = self.source_fetcher.acquire_all(refs, pkg_dir)
            self.last_source_acquisition = [acquisition.to_dict() for acquisition in acquisitions]
            for acquisition in acquisitions:
                findings.extend(acquisition.findings)
                source_path = acquisition.local_path
                if acquisition.reference.kind == SourceKind.signature:
                    continue
                if acquisition.status != "acquired" or source_path is None:
                    continue
                if source_path.is_dir():
                    clam_tree = self.clamav.scan_unpacked_source(str(source_path))
                    findings.extend(clam_tree.findings)
                    findings.extend(self.inspect_source_tree(source_path))
                    continue

                clam_archive = self.clamav.scan_source_archive(str(source_path))
                findings.extend(clam_archive.findings)
                if any(f.blocks_installation for f in clam_archive.findings):
                    continue

                target_dir, archive_findings = self.extractor.extract(str(source_path))
                findings.extend(archive_findings)
                if any(f.blocks_installation for f in archive_findings):
                    continue
                if target_dir:
                    temp_dirs.append(target_dir)

                clam_tree = self.clamav.scan_unpacked_source(str(target_dir))
                findings.extend(clam_tree.findings)
                findings.extend(self.inspect_source_tree(target_dir))
        finally:
            for temp_dir in temp_dirs:
                shutil.rmtree(temp_dir, ignore_errors=True)
            acquisition_dir = getattr(self.source_fetcher, "last_output_dir", None)
            if acquisition_dir:
                shutil.rmtree(acquisition_dir, ignore_errors=True)

        return AnalysisResult(not any(f.blocks_installation for f in findings), "Deep static scan complete", findings)

    def inspect_source_tree(self, root: Path) -> List[Finding]:
        findings: List[Finding] = []
        self._tree_scan_incomplete = False
        precompiled_carriers = []
        precompiled_controls = []
        control_bytes = 0
        npm_manifests = []
        npm_scripts = {}
        npm_bytes = 0
        remaining_bytes = self.max_total_file_bytes
        for path in self._iter_interesting_files(root, all_regular=True):
            rel = str(path.relative_to(root))
            if remaining_bytes <= 0:
                self._tree_scan_incomplete = True
                break
            # Hash ordinary assets too: renaming a known payload must not
            # evade exact-byte intelligence. Large non-code files are streamed
            # through the same stable component-wise no-follow reader.
            self._last_read_bytes = 0
            interesting = self._is_interesting_file(path, root, min(4096, remaining_bytes))
            remaining_bytes -= self._last_read_bytes
            if remaining_bytes <= 0:
                self._tree_scan_incomplete = True
                break
            if not interesting:
                digest = self._read_regular_file(
                    path, min(self.max_hash_file_size, remaining_bytes),
                    allow_larger=False, hash_only=True,
                )
                remaining_bytes -= self._last_read_bytes
                if digest is None:
                    self._tree_scan_incomplete = True
                else:
                    findings.extend(known_payload_digest_findings(str(path), digest.hex(), self.intelligence_snapshot))
                    findings.extend(self._nested_archive_findings(path, self._last_read_prefix))
                continue
            payload = self._read_regular_file(
                path, min(self.max_file_size, remaining_bytes), allow_larger=False,
            )
            remaining_bytes -= self._last_read_bytes
            if payload is None:
                self._tree_scan_incomplete = True
                continue
            findings.extend(known_payload_findings(str(path), payload, self.intelligence_snapshot))
            if is_editor_tasks_path(path.relative_to(root).as_posix()):
                # JSON command fields have their own semantics. In particular,
                # labels and descriptions must never become shell commands.
                task_findings = editor_task_findings(
                    payload, str(path), phase=Phase.unpacked_source_scan,
                )
                findings.extend(task_findings)
                if any(f.rule_id == "EDITOR-TASK-INSPECTION-INCOMPLETE-001" for f in task_findings):
                    self._tree_scan_incomplete = True
                continue
            nested = self._nested_archive_findings(path, payload[:512])
            if nested:
                findings.extend(nested)
                continue
            if any(part in VENDORED_DIRS for part in path.relative_to(root).parts):
                findings.append(self._finding(
                    "DEEPSTATIC-VENDORED-DEPS",
                    str(path),
                    Severity.LOW,
                    "Vendored dependency directory is present in the source tree.",
                    "Review vendored code provenance if this is unexpected.",
                    False,
                    rel,
                    EvidenceQuality.weak_heuristic,
                ))
            precompiled_kind = classify_python_precompiled(str(path), payload)
            if precompiled_kind:
                precompiled_carriers.append((str(path), precompiled_kind))
                findings.extend(python_precompiled_findings(
                    precompiled_kind, str(path), Phase.unpacked_source_scan,
                ))
                # A suffix only selects review candidates.  Plain text renamed
                # .pyc/.pyo/.pyd must retain the existing text-rule inspection.
                if precompiled_kind != PYTHON_PRECOMPILED_CANDIDATE or self._is_binary(payload):
                    continue
            if path.name in {"package.json", "pnpm-lock.yaml"}:
                try:
                    metadata_text = payload.decode("utf-8")
                except UnicodeError:
                    self._tree_scan_incomplete = True
                    continue
                findings.extend(inspect_npm_metadata(
                    str(path), metadata_text, lockfile=path.name == "pnpm-lock.yaml",
                ))
            if self._is_binary(payload):
                findings.append(self._finding(
                    "DEEPSTATIC-BINARY-BLOB",
                    str(path),
                    Severity.MEDIUM,
                    "Source tree contains an unexpected binary blob.",
                    "Verify this binary is documented and expected.",
                    False,
                    rel,
                    EvidenceQuality.strong_heuristic,
                ))
                continue
            text = payload.decode("utf-8", errors="replace")
            if path.name in {"package.json", "index.js"}:
                npm_bytes += len(payload)
                if npm_bytes <= 8 * 1024 * 1024:
                    if path.name == "package.json":
                        npm_manifests.append((str(path), text))
                    else:
                        npm_scripts[str(path)] = text
                else:
                    self._tree_scan_incomplete = True
            if is_precompiled_control_script(str(path)):
                control_bytes += len(payload)
                if control_bytes <= 5 * 1024 * 1024:
                    precompiled_controls.append((str(path), text))
            findings.extend(self._inspect_text_file(path, text))
        for manifest_path, manifest_text in npm_manifests:
            findings.extend(inspect_npm_lifecycle(
                manifest_path, manifest_text, npm_scripts,
                intelligence_snapshot=self.intelligence_snapshot,
            ))
        if precompiled_carriers:
            execution = analyze_precompiled_execution(root, precompiled_carriers, precompiled_controls)
            findings.extend(execution.findings)
            if not execution.complete or control_bytes > 5 * 1024 * 1024:
                self._tree_scan_incomplete = True
        if self._tree_scan_incomplete:
            findings.append(self._finding(
                "DEEPSTATIC-INSPECTION-INCOMPLETE-001",
                str(root),
                Severity.HIGH,
                "Acquired source traversal or a required candidate read exceeded a safety bound or could not be completed safely.",
                "Do not build or install until the complete source tree can be inspected within the configured bounds.",
                True,
                "bounded source-tree inspection did not complete",
                EvidenceQuality.strong_heuristic,
            ))
        # Name/path and campaign metadata checks share the same strict reader.
        # One unsupported document needs one metadata coverage item, while
        # findings for different documents and distinct evidence stay separate.
        metadata_coverage = set()
        unique_findings = []
        for finding in findings:
            if finding.rule_id == "NPM-METADATA-INSPECTION-INCOMPLETE-001":
                if finding.file_path in metadata_coverage:
                    continue
                metadata_coverage.add(finding.file_path)
            unique_findings.append(finding)
        return unique_findings

    def _nested_archive_findings(self, path: Path, prefix: bytes) -> List[Finding]:
        if not (
            path.name.lower().endswith(NESTED_ARCHIVE_SUFFIXES)
            or _classify_artifact(prefix, pe_valid=False) in _ARCHIVE_KINDS
        ):
            return []
        return [self._finding(
            "DEEPSTATIC-NESTED-ARCHIVE-UNINSPECTED-001",
            str(path), Severity.HIGH,
            "Acquired source contains an archive or compressed carrier that AuraScan did not recursively expand and inspect.",
            "Do not build or install until nested content has been inspected independently within equivalent safety bounds.",
            True, "nested archive or compressed content was not recursively inspected",
            EvidenceQuality.strong_heuristic,
        )]

    def _inspect_text_file(self, path: Path, text: str) -> List[Finding]:
        active_text = self._strip_comment_lines(text)
        rules = [
            ("DEEPSTATIC-NETWORK-FETCH", r"\b(curl|wget|git\s+clone)\b[^\n]*(https?|git|ssh)://", Severity.MEDIUM, "Source file contains an additional network fetch."),
            ("DEEPSTATIC-CREDENTIAL-PATH", r"(\$HOME|~)/\.(ssh|gnupg|aws|env)\b|(\$HOME|~)/\.config/(?!systemd/user)|/home/[^/\s]+/\.(ssh|gnupg|aws|env)\b|/home/[^/\s]+/\.config/(?!systemd/user)", Severity.CRITICAL, "Source file references credential-sensitive paths."),
            ("DEEPSTATIC-TOKEN-REFERENCE", r"\b(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|API_KEY|PRIVATE_KEY)\b", Severity.HIGH, "Source file references credential or token names."),
            ("DEEPSTATIC-BASE64-EXEC", r"base64\s+-d[^|\n]*\|\s*(sh|bash|python)", Severity.CRITICAL, "Source file decodes base64 and executes it."),
            ("DEEPSTATIC-EVAL-CHAIN", r"\beval\b.*(\$\(|base64|curl|wget)", Severity.HIGH, "Source file contains an eval chain."),
            ("DEEPSTATIC-HEREDOC-PAYLOAD", r"<<[-']?\w+.*\n.*(curl|base64|chmod\s+\+s)", Severity.MEDIUM, "Source file contains a suspicious heredoc payload."),
            ("DEEPSTATIC-SUID-LOGIC", r"(chmod\s+[0-7]*[46][0-7]{2}|chmod\s+\+s|chown\s+root)", Severity.HIGH, "Source file contains suspicious chmod/chown or suid logic."),
            ("DEEPSTATIC-CRON-PERSISTENCE", r"(@reboot|crontab\s+-|/etc/cron)", Severity.HIGH, "Source file contains cron persistence indicators."),
            ("DEEPSTATIC-OBFUSCATED-CODE", r"(fromCharCode|atob\s*\(|\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2})", Severity.MEDIUM, "Source file contains obfuscation indicators."),
            ("DEEPSTATIC-SUPPLYCHAIN-AUR-JS-20260611", r"\b(?:npm\s+(?:install|i)|bun\s+(?:add|install)|yarn\s+add|pnpm\s+(?:add|install))\b[^#\n]*(?:atomic-lockfile|lockfile-js|js-digest)\b", Severity.CRITICAL, "Source file invokes a known malicious JavaScript dependency from the June 2026 AUR campaign."),
        ]
        findings: List[Finding] = self._inspect_systemd_text(path, active_text)
        for rule_id, pattern, severity, explanation in rules:
            match = re.search(pattern, active_text, re.I | re.S)
            if match:
                line = active_text[:match.start()].count("\n") + 1
                findings.append(self._finding(
                    rule_id,
                    str(path),
                    severity,
                    explanation,
                    "Review this file as text before trusting the source tree.",
                    severity == Severity.CRITICAL,
                    self._line_at(active_text, line),
                    EvidenceQuality.confirmed_static_pattern if severity == Severity.CRITICAL else EvidenceQuality.strong_heuristic,
                    line,
                ))

        signals = find_remote_access_backdoor_signals(active_text)
        if len(signals) >= 2 and any(signal.remote_anchor for signal in signals):
            findings.append(self._finding(
                "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001",
                str(path),
                Severity.CRITICAL,
                "Source combines multiple behaviors associated with a root remote-access backdoor.",
                "Do not build this source revision; preserve its provenance and investigate any prior installation from trusted media.",
                True,
                "Correlated signals: " + "; ".join(signal.label for signal in signals),
                EvidenceQuality.confirmed_static_pattern,
                min(signal.line_number for signal in signals),
            ))

        remote_stage_analysis = analyze_remote_stage_execution(text)
        remote_stage_signals = remote_stage_analysis.signals
        if not remote_stage_analysis.complete:
            self._tree_scan_incomplete = True
        if remote_stage_signals:
            findings.append(self._finding(
                "DEEPSTATIC-REMOTE-STAGE-EXEC-001",
                str(path),
                Severity.CRITICAL,
                "Acquired source logic downloads remote content into a local artifact and then executes that artifact or derived content.",
                "Do not build this source revision until the undeclared remote stage and its integrity controls have been independently reviewed.",
                True,
                "Correlated signals: " + "; ".join(
                    signal.label for signal in remote_stage_signals
                ),
                EvidenceQuality.confirmed_static_pattern,
                min(signal.line_number for signal in remote_stage_signals),
            ))

        carrier_analysis = analyze_carrier_execution(text)
        if not carrier_analysis.complete:
            self._tree_scan_incomplete = True
        carrier_signals = carrier_analysis.signals
        if carrier_signals and not remote_stage_signals:
            findings.append(self._finding(
                "DEEPSTATIC-OPAQUE-CARRIER-EXEC-001",
                str(path),
                Severity.CRITICAL,
                "Acquired source logic decodes local content into an artifact that it later executes, or invokes a media, document, or font-named artifact as code.",
                "Do not build this source revision until the complete carrier, transformation, and execution chain has been independently reviewed.",
                True,
                "Correlated signals: " + "; ".join(
                    signal.label for signal in carrier_signals
                ),
                EvidenceQuality.confirmed_static_pattern,
                min(signal.line_number for signal in carrier_signals),
            ))

        if path.name == "package.json":
            findings.extend(self._inspect_package_json(path, text))
        if path.name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
            findings.extend(inspect_npm_campaign_metadata(str(path), text, self.intelligence_snapshot))
        if path.suffix in {".sh", ".bash", ".zsh"} or (
            not path.suffix and text.startswith("#!") and
            re.match(r"^#![^\n]*\b(?:sh|bash|zsh)\b", text)
        ):
            findings.extend(analyze_npm_install_commands(text, str(path), Phase.unpacked_source_scan, self.intelligence_snapshot))
        if path.name == "setup.py" and re.search(r"\b(urlopen|requests\.|curl|wget|subprocess)\b", text):
            findings.append(self._finding(
                "DEEPSTATIC-SETUPPY-SUSPICIOUS",
                str(path),
                Severity.HIGH,
                "setup.py contains network or subprocess indicators.",
                "Inspect setup.py manually; AuraScan treated it as text only.",
                False,
                "setup.py inspected without execution",
            ))
        if self._looks_minified(path, text):
            findings.append(self._finding(
                "DEEPSTATIC-MINIFIED-FILE",
                str(path),
                Severity.LOW,
                "Source tree contains a minified or dense generated-looking file.",
                "Review provenance or prefer auditable source form.",
                False,
                path.name,
                EvidenceQuality.weak_heuristic,
            ))
        return findings

    def _inspect_systemd_text(self, path: Path, text: str) -> List[Finding]:
        findings: List[Finding] = []
        if self._is_systemd_unit_file(path):
            findings.append(self._finding(
                "DEEPSTATIC-SYSTEMD-UNIT-001",
                str(path),
                Severity.MEDIUM,
                "Source tree contains a systemd service or timer unit file.",
                "Review the unit file if this service behavior is unexpected.",
                False,
                path.name,
                EvidenceQuality.weak_heuristic,
                1,
            ))

        checks = [
            (
                "DEEPSTATIC-SYSTEMD-USER-001",
                r"((\$HOME|~|/home/[^/\s]+)?/\.config/systemd/user|systemctl\s+--user[^\n;|&]*\b(enable|start)\b)",
                Severity.HIGH,
                "Source text references user-level systemd persistence.",
            ),
            (
                "DEEPSTATIC-SYSTEMD-AUTO-001",
                r"\bsystemctl\b(?![^\n]*--user)[^\n;|&]*\b(enable|start)\b",
                Severity.HIGH,
                "Source text enables or starts a systemd service.",
            ),
        ]
        for rule_id, pattern, severity, explanation in checks:
            match = re.search(pattern, text, re.I)
            if not match:
                continue
            line = text[:match.start()].count("\n") + 1
            findings.append(self._finding(
                rule_id,
                str(path),
                severity,
                explanation,
                "Review this file as text before trusting the source tree.",
                False,
                self._line_at(text, line),
                EvidenceQuality.strong_heuristic,
                line,
            ))
        return findings

    def _is_systemd_unit_file(self, path: Path) -> bool:
        return path.suffix in {".service", ".timer"}

    def _strip_comment_lines(self, text: str) -> str:
        lines = []
        for line in text.splitlines():
            stripped = line.lstrip()
            lines.append("" if stripped.startswith("#") else line)
        return "\n".join(lines)

    def _inspect_package_json(self, path: Path, text: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = strict_json_object(text)
        except MetadataIncomplete:
            self._tree_scan_incomplete = True
            return findings
        if not isinstance(data, dict):
            self._tree_scan_incomplete = True
            return findings
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            self._tree_scan_incomplete = True
            return findings
        for name in ("preinstall", "install", "postinstall", "prepare"):
            if name in scripts:
                if not isinstance(scripts[name], str):
                    self._tree_scan_incomplete = True
                    continue
                findings.append(self._finding(
                    "DEEPSTATIC-NPM-INSTALL-SCRIPT",
                    str(path),
                    Severity.HIGH,
                    f"package.json defines a {name} script.",
                    "Review install-time package scripts manually; AuraScan did not execute them.",
                    False,
                    f"declared {name} lifecycle script; content withheld",
                ))
        dependencies = data.get("dependencies", {})
        development_dependencies = data.get("devDependencies", {})
        if not isinstance(dependencies, dict) or not isinstance(development_dependencies, dict):
            self._tree_scan_incomplete = True
            return findings
        deps = set(dependencies) | set(development_dependencies)
        for dep in deps:
            if dep.lower().replace("-", "") in {"reqeusts", "lodahs", "expres"}:
                findings.append(self._finding(
                    "DEEPSTATIC-TYPOSQUAT-INDICATOR",
                    str(path),
                    Severity.MEDIUM,
                    "Dependency name resembles a common typosquat pattern.",
                    "Verify dependency provenance.",
                    False,
                    dep,
                ))
        return findings

    def _is_interesting_file(self, path: Path, root: Path, sniff_limit: int = 4096) -> bool:
        rel_parts = path.relative_to(root).parts
        if ".git" in rel_parts:
            # VCS internals are hash evidence only. Do not interpret Git data
            # as shell control text, but do not exempt archive-supplied bytes
            # from a known-payload lookup based on this directory name.
            return False
        try:
            metadata = path.lstat()
        except OSError:
            self._tree_scan_incomplete = True
            return True
        return (
            any(part in VENDORED_DIRS for part in rel_parts)
            or is_editor_tasks_path(path.relative_to(root).as_posix())
            or path.name in INTERESTING_NAMES
            or path.name.startswith(".")
            or path.suffix in TEXT_SUFFIXES
            or is_python_precompiled_path(str(path))
            or "__pycache__" in rel_parts
            or path.name.lower().endswith(NESTED_ARCHIVE_SUFFIXES)
            or ".min." in path.name
            or bool(metadata.st_mode & stat.S_IXUSR)
            or "systemd" in rel_parts
            or "cron" in rel_parts
            or (not path.suffix and self._has_text_shebang(path, sniff_limit))
        )

    def _iter_interesting_files(self, root: Path, all_regular: bool = False) -> Iterable[Path]:
        try:
            root_metadata = root.lstat()
        except OSError:
            self._tree_scan_incomplete = True
            return
        if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
            self._tree_scan_incomplete = True
            return

        entry_count = 0
        candidate_count = 0
        pending_directories = [root]
        while pending_directories:
            current_path = pending_directories.pop()
            try:
                iterator = os.scandir(str(current_path))
            except OSError:
                self._tree_scan_incomplete = True
                continue
            try:
                with iterator:
                    for entry in iterator:
                        entry_count += 1
                        if entry_count > self.max_tree_entries:
                            self._tree_scan_incomplete = True
                            return
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                        except OSError:
                            self._tree_scan_incomplete = True
                            continue
                        if stat.S_ISLNK(metadata.st_mode):
                            # Build tooling may follow a link even though this
                            # static scanner deliberately does not.  Skipping
                            # it can never produce an authorized clear result.
                            self._tree_scan_incomplete = True
                            continue
                        path = Path(entry.path)
                        if stat.S_ISDIR(metadata.st_mode):
                            if all_regular or entry.name != ".git":
                                pending_directories.append(path)
                            continue
                        if not stat.S_ISREG(metadata.st_mode):
                            continue
                        if not all_regular and not self._is_interesting_file(path, root):
                            continue
                        candidate_count += 1
                        if candidate_count > self.max_candidates:
                            self._tree_scan_incomplete = True
                            return
                        yield path
            except OSError:
                self._tree_scan_incomplete = True

    def _has_text_shebang(self, path: Path, limit: int = 4096) -> bool:
        payload = self._read_regular_file(path, limit, allow_larger=True)
        if payload is None:
            self._tree_scan_incomplete = True
        return bool(payload is not None and payload.startswith(b"#!") and b"\x00" not in payload)

    def _read_candidate(self, path: Path) -> Optional[bytes]:
        return self._read_regular_file(path, self.max_file_size, allow_larger=False)

    def _read_regular_file(
        self,
        path: Path,
        limit: int,
        *,
        allow_larger: bool,
        hash_only: bool = False,
    ) -> Optional[bytes]:
        self._last_read_bytes = 0
        self._last_read_prefix = b""
        file_descriptor = -1
        directory_descriptors = []
        directory_records = []
        if (
            limit < 0
            or not getattr(os, "O_NOFOLLOW", 0)
            or not getattr(os, "O_DIRECTORY", 0)
        ):
            return None

        def directory_identity(item):
            return (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            )

        def file_identity(item):
            return (
                item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
                item.st_ctime_ns, item.st_mode, item.st_uid, item.st_gid,
                item.st_nlink,
            )

        def parents_unchanged():
            for parent_fd, component, child_fd, expected in directory_records:
                current = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    directory_identity(current) != expected
                    or directory_identity(os.fstat(child_fd)) != expected
                ):
                    return False
            return True

        try:
            # O_NOFOLLOW on the leaf alone does not protect an ancestor that
            # was replaced by a link after discovery.  Walk from the absolute
            # root through held directory descriptors, then revalidate every
            # component and the final pathname before accepting captured bytes.
            if ".." in Path(path).parts:
                return None
            absolute = Path(os.path.abspath(str(path)))
            parts = absolute.parts[1:]
            if not parts or len(parts) > 128 or len(os.fsencode(str(absolute))) > 4096:
                return None
            directory_flags = (
                os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
            )
            directory_fd = os.open(absolute.anchor, directory_flags)
            directory_descriptors.append(directory_fd)
            for component in parts[:-1]:
                expected = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISDIR(expected.st_mode):
                    return None
                child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                directory_descriptors.append(child_fd)
                identity = directory_identity(expected)
                if directory_identity(os.fstat(child_fd)) != identity:
                    return None
                directory_records.append((directory_fd, component, child_fd, identity))
                directory_fd = child_fd
            before_path = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(before_path.st_mode) or not parents_unchanged():
                return None
            file_descriptor = os.open(
                parts[-1],
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            before = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or file_identity(before_path) != file_identity(before)
            ):
                return None
            if not allow_larger and before.st_size > limit:
                return None
            payload = bytearray()
            prefix = bytearray()
            digest = hashlib.sha256() if hash_only else None
            while self._last_read_bytes < limit:
                chunk = os.read(file_descriptor, min(65536, limit - self._last_read_bytes))
                if not chunk:
                    break
                self._last_read_bytes += len(chunk)
                if len(prefix) < 512:
                    prefix.extend(chunk[:512 - len(prefix)])
                if digest is not None:
                    digest.update(chunk)
                else:
                    payload.extend(chunk)
            after = os.fstat(file_descriptor)
            current_path = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
            if (
                file_identity(before) != file_identity(after)
                or file_identity(after) != file_identity(current_path)
                or not parents_unchanged()
            ):
                return None
            if not allow_larger and (self._last_read_bytes > limit or self._last_read_bytes != after.st_size):
                return None
            if digest is not None:
                self._last_read_prefix = bytes(prefix)
                return digest.digest()
            return bytes(payload[:limit])
        except OSError:
            return None
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            for directory_fd in reversed(directory_descriptors):
                os.close(directory_fd)

    def _is_binary(self, payload: bytes) -> bool:
        chunk = payload[:4096]
        if not chunk:
            return False
        if b"\x7fELF" in chunk[:8]:
            return True
        return b"\x00" in chunk

    def _looks_minified(self, path: Path, text: str) -> bool:
        if path.suffix not in {".js", ".css"}:
            return False
        lines = text.splitlines() or [text]
        return max(len(line) for line in lines) > 1000

    def _line_at(self, text: str, line_number: int) -> str:
        lines = text.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1].strip()[:300]
        return ""

    def _finding(
        self,
        rule_id: str,
        file_path: str,
        severity: Severity,
        explanation: str,
        recommendation: str,
        blocks: bool,
        evidence: str = "",
        evidence_quality: EvidenceQuality = EvidenceQuality.strong_heuristic,
        line_number: Optional[int] = None,
        phase: Phase = Phase.unpacked_source_scan,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            package_name="unknown",
            package_version="unknown",
            phase=phase,
            source=Source.deterministic_rule,
            severity=severity,
            confidence=Confidence.CONFIRMED if evidence_quality == EvidenceQuality.confirmed_static_pattern else Confidence.HIGH,
            evidence_quality=evidence_quality,
            file_path=file_path,
            line_number=line_number,
            explanation=explanation,
            recommendation=recommendation,
            blocks_installation=blocks,
            requires_manual_review=not blocks,
            evidence_snippet=evidence,
        )
