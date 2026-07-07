import json
import os
import re
import shutil
from pathlib import Path
from typing import Iterable, List, Optional

from aurascan.analyzers.base import BaseAnalyzer
from aurascan.analyzers.clamav import ClamAVAnalyzer
from aurascan.core.archive import SafeArchiveExtractor
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
    "setup.py", "pyproject.toml", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "Cargo.toml", "Cargo.lock", "go.mod",
    "go.sum", "composer.json", "Gemfile",
}
TEXT_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".service", ".timer", ".cron"}
VENDORED_DIRS = {"node_modules", "vendor", "third_party", "deps"}


class DeepStaticAnalyzer(BaseAnalyzer):
    def __init__(
        self,
        extractor: Optional[SafeArchiveExtractor] = None,
        clamav: Optional[ClamAVAnalyzer] = None,
        source_parser: Optional[SourceParser] = None,
        source_fetcher: Optional[SourceFetcher] = None,
        max_file_size: int = 1024 * 1024,
    ):
        self.extractor = extractor or SafeArchiveExtractor()
        self.clamav = clamav or ClamAVAnalyzer()
        self.source_parser = source_parser or SourceParser()
        self.source_fetcher = source_fetcher or SourceFetcher()
        self.max_file_size = max_file_size
        self.last_source_acquisition = []

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
        for path in self._iter_interesting_files(root):
            rel = str(path.relative_to(root))
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
                continue
            if self._is_binary(path):
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
            text = self._read_text(path)
            if text is None:
                continue
            findings.extend(self._inspect_text_file(path, text))
        return findings

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

        if path.name == "package.json":
            findings.extend(self._inspect_package_json(path, text))
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
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings
        scripts = data.get("scripts", {})
        for name in ("preinstall", "install", "postinstall", "prepare"):
            if name in scripts:
                findings.append(self._finding(
                    "DEEPSTATIC-NPM-INSTALL-SCRIPT",
                    str(path),
                    Severity.HIGH,
                    f"package.json defines a {name} script.",
                    "Review install-time package scripts manually; AuraScan did not execute them.",
                    False,
                    f"{name}: {scripts[name]}",
                ))
        deps = set(data.get("dependencies", {})) | set(data.get("devDependencies", {}))
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

    def _iter_interesting_files(self, root: Path) -> Iterable[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(root).parts
            if any(part in VENDORED_DIRS for part in rel_parts):
                yield path
                continue
            if (
                path.name in INTERESTING_NAMES
                or path.name.startswith(".")
                or path.suffix in TEXT_SUFFIXES
                or ".min." in path.name
                or os.access(path, os.X_OK)
                or "systemd" in rel_parts
                or "cron" in rel_parts
            ):
                yield path

    def _is_binary(self, path: Path) -> bool:
        try:
            chunk = path.read_bytes()[:4096]
        except OSError:
            return False
        if not chunk:
            return False
        if b"\x7fELF" in chunk[:8]:
            return True
        return b"\x00" in chunk

    def _read_text(self, path: Path) -> Optional[str]:
        try:
            if path.stat().st_size > self.max_file_size:
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

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
