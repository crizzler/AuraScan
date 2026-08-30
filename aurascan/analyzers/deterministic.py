import os
import re
import shlex
from pathlib import Path
from typing import List
from aurascan.analyzers.base import BaseAnalyzer
from aurascan.analyzers.aur_propagation import find_aur_repository_propagation_signals
from aurascan.analyzers.remote_access import (
    find_remote_access_backdoor_signals,
    mask_shell_quoted_text,
    shell_command_pattern,
)
from aurascan.analyzers.remote_stage import (
    analyze_carrier_execution,
    analyze_remote_stage_execution,
)
from aurascan.core.models import AnalysisResult, Finding, Phase, Source, Severity, Confidence, EvidenceQuality
from aurascan.core.package_archive import (
    PACKAGE_HOOK_ABSENT,
    PACKAGE_HOOK_RESOLVED,
    capture_package_install_hook,
)

class Rule:
    def __init__(self, rule_id: str, pattern: str, severity: Severity, explanation: str, blocks: bool):
        self.rule_id = rule_id
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.explanation = explanation
        self.blocks = blocks

RULES = [
    Rule("CRED-SSH-001", r"~\/\.ssh\/[a-zA-Z0-9_]+", Severity.CRITICAL, "Attempted read of ~/.ssh path.", True),
    Rule("CRED-GPG-001", r"~\/\.gnupg\/", Severity.CRITICAL, "Attempted read of ~/.gnupg path.", True),
    Rule("CRED-ENV-001", r"~\/\.env", Severity.HIGH, "Attempted read of ~/.env file.", False),
    Rule("NET-EXEC-001", r"(curl|wget)[^|]*\|\s*(sh|bash)", Severity.CRITICAL, "Remote execution (curl|wget piped to shell).", True),
    Rule("EXEC-B64-001", r"base64\s+-d[^|]*\|\s*(sh|bash)", Severity.CRITICAL, "Base64 decode piped to shell.", True),
    Rule(
        "SUPPLYCHAIN-AUR-JS-20260611",
        r"\b(?:npm\s+(?:install|i)|bun\s+(?:add|install)|yarn\s+add|pnpm\s+(?:add|install))\b[^#\n]*(?:atomic-lockfile|lockfile-js|js-digest)\b",
        Severity.CRITICAL,
        "Known malicious JavaScript dependency from the June 2026 AUR campaign.",
        True,
    ),
    Rule(
        "EXEC-EVAL-NET-001",
        r"\beval\b[^#\n]*(\$\(.*\b(curl|wget|base64|printf|xxd)\b|`.*\b(curl|wget|base64|printf|xxd)\b|\b(curl|wget)\b|\bbase64\s+-d\b)",
        Severity.CRITICAL,
        "Dynamic eval execution is combined with network fetch or decoded content.",
        True,
    ),
    Rule(
        "EXEC-EVAL-001",
        r"\beval\b\s*(\"?\$\(|`|['\"]?\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?|\$\{[^}]+})",
        Severity.HIGH,
        "Dynamic shell evaluation via eval.",
        False,
    ),
    Rule(
        "PRIV-SUDOERS-NOPASSWD-001",
        r"(?:^|['\"])[ \t]*(?:%?[A-Za-z_][A-Za-z0-9_.-]*|ALL)[ \t]+[^=\s]+[ \t]*="
        r"[ \t]*(?:\([^\n)]*\)[ \t]*)?NOPASSWD[ \t]*:",
        Severity.CRITICAL,
        "Package logic grants passwordless sudo execution.",
        True,
    ),
    Rule(
        "PRIV-SUDOERS-DROPIN-001",
        r"(?:(?:\$pkgdir|\$\{pkgdir\})/etc/sudoers(?:\.d(?:/[^\s\"']*)?)?\b|"
        r"\b(?:install|cp|mv|tee|chmod|chown)\b[^\n]*/etc/sudoers(?:\.d(?:/[^\s\"']*)?)?\b)",
        Severity.HIGH,
        "Package logic installs or references privileged sudo policy.",
        False,
    ),
    Rule(
        "SYS-SYSTEMD-USER-001",
        r"(\$HOME|~|/home/[^/\s]+)?/\.config/systemd/user|systemctl\s+--user\s+(enable|start)",
        Severity.HIGH,
        "Package logic references user-level systemd persistence.",
        False,
    ),
    Rule(
        "SYS-SYSTEMD-AUTO-001",
        r"\bsystemctl\b(?!\s+--user)[^#\n;|&]*\b(enable|start)\b",
        Severity.HIGH,
        "Package logic enables or starts a systemd service.",
        False,
    ),
    Rule(
        "SYS-SYSTEMD-UNIT-001",
        r"(/etc/systemd/system|/usr/lib/systemd/system)[^\s\"']*\.service",
        Severity.MEDIUM,
        "Package logic installs or writes a systemd service unit file.",
        False,
    ),
    Rule(
        "SYS-CRON-REBOOT-001",
        r"@reboot\b",
        Severity.HIGH,
        "Package logic creates cron startup persistence.",
        False,
    ),
    Rule(
        "SYS-CRONTAB-001",
        r"\bcrontab\b\s+(-|[^#\n]*)",
        Severity.HIGH,
        "Package logic uses the crontab command.",
        False,
    ),
    Rule(
        "SYS-CRON-FILE-001",
        r"(/etc/cron\.d|/etc/crontab|/var/spool/cron)",
        Severity.HIGH,
        "Package logic writes or references system cron locations.",
        False,
    ),
]

COMMENT_FILTERED_RULE_IDS = {
    "EXEC-EVAL-NET-001",
    "EXEC-EVAL-001",
    "SUPPLYCHAIN-AUR-JS-20260611",
    "PRIV-SUDOERS-NOPASSWD-001",
    "PRIV-SUDOERS-DROPIN-001",
    "SYS-SYSTEMD-USER-001",
    "SYS-SYSTEMD-AUTO-001",
    "SYS-SYSTEMD-UNIT-001",
    "SYS-CRON-REBOOT-001",
    "SYS-CRONTAB-001",
    "SYS-CRON-FILE-001",
}

SECRET_FREE_EVIDENCE = {
    "PRIV-SUDOERS-NOPASSWD-001": "sudoers policy grants passwordless execution",
    "PRIV-SUDOERS-DROPIN-001": "package logic targets a sudoers policy path",
}

_SUDO_COMMAND = shell_command_pattern("sudo")
_CHMOD_COMMAND = shell_command_pattern("chmod")
_SUID_MODE = re.compile(r"(?:0?4[0-7]{3}|u\+s|\+s)", re.IGNORECASE)
_SOURCE_ASSIGNMENT_START = re.compile(
    r"^[ \t]*source(?:_(?:x86_64|i686|pentium4|aarch64|armv7h|armv6h|riscv64|loong64))?"
    r"[ \t]*=[ \t]*\(",
    re.IGNORECASE | re.MULTILINE,
)
_HYPRLAND_FIXES_SOURCE = re.compile(
    r"(?:https?|git\+https)://github\.com/iusearch-hyprlandbtw/hyprland-fixes"
    r"(?:\.git)?(?:[#'\"\s]|$)",
    re.IGNORECASE,
)

class DeterministicAnalyzer(BaseAnalyzer):
    def analyze_package(self, pkg_path: str) -> AnalysisResult:
        captured = capture_package_install_hook(Path(pkg_path))
        if captured.status == PACKAGE_HOOK_ABSENT:
            return AnalysisResult(True, "No package install hook was declared.", [])
        if captured.status != PACKAGE_HOOK_RESOLVED:
            finding = Finding(
                rule_id="PACKAGE-INSTALL-HOOK-UNINSPECTED-001",
                package_name="unknown",
                package_version="unknown",
                phase=Phase.install_hook_static,
                source=Source.deterministic_rule,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence_quality=EvidenceQuality.confirmed_static_pattern,
                file_path=str(pkg_path),
                explanation=(
                    "The package archive may contain install-time control data, but AuraScan could "
                    "not obtain a bounded, stable text view of it."
                ),
                recommendation=(
                    "Do not install this package archive until its structure and install hook can "
                    "be inspected safely."
                ),
                false_positive_notes=(
                    "Incomplete inspection is not evidence that the package is malicious."
                ),
                blocks_installation=True,
                requires_manual_review=False,
                evidence_snippet="package install-hook inspection did not complete",
            )
            return AnalysisResult(False, "Package install hook could not be inspected.", [finding])
        findings = self.analyze_content(
            str(pkg_path) + "::/.INSTALL",
            captured.content,
            Phase.install_hook_static,
        )
        safe = not any(finding.blocks_installation for finding in findings)
        return AnalysisResult(
            safe,
            "Package install hook deterministic rules passed."
            if safe
            else "Package install hook deterministic rules failed.",
            findings,
        )

    def analyze_content(self, pkg_path: str, content: str, phase: Phase, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> List[Finding]:
        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines):
            scanned_line = self._strip_shell_comment(line)
            matched_rule_ids = set()
            for rule in RULES:
                if rule.rule_id == "EXEC-EVAL-001" and "EXEC-EVAL-NET-001" in matched_rule_ids:
                    continue
                evidence_line = scanned_line if rule.rule_id in COMMENT_FILTERED_RULE_IDS else line
                if not evidence_line.strip():
                    continue
                match = rule.pattern.search(evidence_line)
                if match:
                    matched_rule_ids.add(rule.rule_id)
                    finding = Finding(
                        rule_id=rule.rule_id,
                        package_name=pkg_name,
                        package_version=pkg_ver,
                        phase=phase,
                        source=Source.deterministic_rule,
                        severity=rule.severity,
                        confidence=Confidence.CONFIRMED,
                        evidence_quality=EvidenceQuality.confirmed_static_pattern,
                        file_path=pkg_path,
                        explanation=rule.explanation,
                        recommendation="Review the script to determine if this pattern is legitimate or malicious.",
                        blocks_installation=rule.blocks,
                        requires_manual_review=not rule.blocks,
                        evidence_snippet=SECRET_FREE_EVIDENCE.get(rule.rule_id, evidence_line.strip()),
                        line_number=i+1
                    )
                    findings.append(finding)
        findings.extend(self._inspect_suid_chmod(pkg_path, lines, phase, pkg_name, pkg_ver))
        active_content = "\n".join(self._strip_shell_comment(line) for line in lines)
        if phase == Phase.pkgbuild_static:
            findings.extend(self._inspect_reported_source(pkg_path, active_content, pkg_name, pkg_ver))
        signals = find_remote_access_backdoor_signals(active_content)
        if len(signals) >= 2 and any(signal.remote_anchor for signal in signals):
            findings.append(Finding(
                rule_id="REMOTE-ADMIN-BACKDOOR-001",
                package_name=pkg_name,
                package_version=pkg_ver,
                phase=phase,
                source=Source.deterministic_rule,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence_quality=EvidenceQuality.confirmed_static_pattern,
                file_path=pkg_path,
                explanation="Package logic combines multiple behaviors associated with a root remote-access backdoor.",
                recommendation="Do not build or install this revision; preserve its provenance and investigate any prior installation from trusted media.",
                blocks_installation=True,
                requires_manual_review=False,
                evidence_snippet="Correlated signals: " + "; ".join(signal.label for signal in signals),
                line_number=min(signal.line_number for signal in signals),
            ))
        remote_stage_analysis = analyze_remote_stage_execution(content)
        remote_stage_signals = remote_stage_analysis.signals
        if not remote_stage_analysis.complete:
            findings.append(Finding(
                rule_id="STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001",
                package_name=pkg_name,
                package_version=pkg_ver,
                phase=phase,
                source=Source.deterministic_rule,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence_quality=EvidenceQuality.confirmed_static_pattern,
                file_path=pkg_path,
                explanation=(
                    "Bounded parsing of package logic did not complete while checking for "
                    "downloaded artifacts that are later executed."
                ),
                recommendation=(
                    "Do not build or install until the complete package logic can be inspected "
                    "within the static-analysis bounds."
                ),
                false_positive_notes=(
                    "Incomplete inspection is not evidence that remote content was downloaded or executed."
                ),
                blocks_installation=True,
                requires_manual_review=False,
                evidence_snippet="bounded remote-stage correlation did not complete",
            ))
        if remote_stage_signals:
            findings.append(Finding(
                rule_id="SUPPLYCHAIN-REMOTE-STAGE-EXEC-001",
                package_name=pkg_name,
                package_version=pkg_ver,
                phase=phase,
                source=Source.deterministic_rule,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence_quality=EvidenceQuality.confirmed_static_pattern,
                file_path=pkg_path,
                explanation=(
                    "Package logic acquires remote content into a local artifact and then executes "
                    "that artifact or content derived from it."
                ),
                recommendation=(
                    "Do not build or install this revision until the complete fetch, integrity "
                    "verification, transformation, and execution chain has been reviewed."
                ),
                false_positive_notes=(
                    "Static correlation does not prove the remote server was contacted, the content "
                    "was malicious, or execution succeeded."
                ),
                blocks_installation=True,
                requires_manual_review=False,
                evidence_snippet="Correlated signals: " + "; ".join(
                    signal.label for signal in remote_stage_signals
                ),
                line_number=min(signal.line_number for signal in remote_stage_signals),
            ))
        carrier_analysis = analyze_carrier_execution(content)
        carrier_signals = carrier_analysis.signals
        # Both correlations share the exact bounded command parser.  The
        # existing incomplete-inspection blocker above therefore covers a
        # carrier analysis which could not complete too.
        if carrier_signals and not remote_stage_signals:
            findings.append(Finding(
                rule_id="SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001",
                package_name=pkg_name,
                package_version=pkg_ver,
                phase=phase,
                source=Source.deterministic_rule,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence_quality=EvidenceQuality.confirmed_static_pattern,
                file_path=pkg_path,
                explanation=(
                    "Package logic decodes local content into an artifact that it later executes, "
                    "or invokes a media, document, or font-named artifact as code."
                ),
                recommendation=(
                    "Do not build or install this revision until the complete carrier, "
                    "transformation, and execution chain has been independently reviewed."
                ),
                false_positive_notes=(
                    "Static correlation does not establish the artifact's bytes, intent, or "
                    "whether execution would succeed."
                ),
                blocks_installation=True,
                requires_manual_review=False,
                evidence_snippet="Correlated signals: " + "; ".join(
                    signal.label for signal in carrier_signals
                ),
                line_number=min(signal.line_number for signal in carrier_signals),
            ))
        if phase in {Phase.pkgbuild_static, Phase.install_hook_static}:
            propagation_signals = find_aur_repository_propagation_signals(
                content,
                dot_prefixed_hook=(
                    phase == Phase.install_hook_static
                    and os.path.basename(pkg_path).startswith(".")
                ),
            )
            if propagation_signals:
                findings.append(Finding(
                    rule_id="SUPPLYCHAIN-AUR-REPO-PROPAGATION-001",
                    package_name=pkg_name,
                    package_version=pkg_ver,
                    phase=phase,
                    source=Source.deterministic_rule,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence_quality=EvidenceQuality.confirmed_static_pattern,
                    file_path=pkg_path,
                    explanation="Package logic correlates an AUR Git remote with repository mutation or staging and a Git push.",
                    recommendation="Do not build or install this revision; preserve its package metadata and review the complete propagation logic from a trusted environment.",
                    blocks_installation=True,
                    requires_manual_review=False,
                    evidence_snippet="Correlated signals: " + "; ".join(
                        signal.label for signal in propagation_signals
                    ),
                    line_number=min(signal.line_number for signal in propagation_signals),
                ))
        if phase == Phase.install_hook_static:
            findings.extend(self._inspect_privileged_install_hook(pkg_path, lines, pkg_name, pkg_ver))
        return findings

    def _inspect_privileged_install_hook(self, pkg_path: str, lines: List[str], pkg_name: str, pkg_ver: str) -> List[Finding]:
        for index, line in enumerate(lines):
            active_line = self._strip_shell_comment(line)
            masked_line = mask_shell_quoted_text(active_line)
            for match in _SUDO_COMMAND.finditer(masked_line):
                segment_end = self._shell_segment_end(masked_line, match.end())
                remainder = active_line[match.end():segment_end]
                if self._has_explicit_non_root_sudo_user(remainder):
                    continue
                return [Finding(
                    rule_id="EXEC-INSTALL-HOOK-SUDO-001",
                    package_name=pkg_name,
                    package_version=pkg_ver,
                    phase=Phase.install_hook_static,
                    source=Source.deterministic_rule,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence_quality=EvidenceQuality.confirmed_static_pattern,
                    file_path=pkg_path,
                    explanation="Install hook invokes sudo even though package install hooks already run with package-manager privileges.",
                    recommendation="Do not install this package until the privileged hook and invoked executable have been fully reviewed.",
                    blocks_installation=True,
                    requires_manual_review=False,
                    evidence_snippet="privileged sudo invocation in install hook",
                    line_number=index + 1,
                )]
        return []

    def _inspect_reported_source(
        self,
        pkg_path: str,
        active_content: str,
        pkg_name: str,
        pkg_ver: str,
    ) -> List[Finding]:
        search_position = 0
        while True:
            assignment = _SOURCE_ASSIGNMENT_START.search(active_content, search_position)
            if assignment is None:
                return []
            array_end = self._shell_array_end(active_content, assignment.end())
            if array_end is None:
                return []
            source_match = _HYPRLAND_FIXES_SOURCE.search(active_content, assignment.end(), array_end)
            if source_match is None:
                search_position = array_end + 1
                continue
            return [Finding(
                rule_id="SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828",
                package_name=pkg_name,
                package_version=pkg_ver,
                phase=Phase.pkgbuild_static,
                source=Source.deterministic_rule,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence_quality=EvidenceQuality.confirmed_static_pattern,
                file_path=pkg_path,
                explanation="Declared source points to the repository reported for the August 2026 hyprland-fixes root backdoor.",
                recommendation="Do not build or install this revision; preserve its package and commit metadata for review.",
                blocks_installation=True,
                requires_manual_review=False,
                evidence_snippet="reported hyprland-fixes source repository",
                line_number=active_content[:source_match.start()].count("\n") + 1,
            )]

    def _shell_array_end(self, text: str, start: int) -> int:
        depth = 1
        quote = ""
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if quote == "'":
                if char == "'":
                    quote = ""
                continue
            if quote == '"':
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quote = ""
                continue
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _inspect_suid_chmod(
        self,
        pkg_path: str,
        lines: List[str],
        phase: Phase,
        pkg_name: str,
        pkg_ver: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        for index, line in enumerate(lines):
            active_line = self._strip_shell_comment(line)
            masked_line = mask_shell_quoted_text(active_line)
            for match in _CHMOD_COMMAND.finditer(masked_line):
                segment_end = self._shell_segment_end(masked_line, match.end())
                try:
                    arguments = shlex.split(active_line[match.end():segment_end], posix=True)
                except ValueError:
                    arguments = []
                if not any(_SUID_MODE.fullmatch(argument) for argument in arguments):
                    continue
                findings.append(Finding(
                    rule_id="SYS-CHMOD-001",
                    package_name=pkg_name,
                    package_version=pkg_ver,
                    phase=phase,
                    source=Source.deterministic_rule,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence_quality=EvidenceQuality.confirmed_static_pattern,
                    file_path=pkg_path,
                    explanation="Package logic applies a set-user-ID or set-group-ID permission mode.",
                    recommendation="Review the script to determine if this pattern is legitimate or malicious.",
                    blocks_installation=True,
                    requires_manual_review=False,
                    evidence_snippet="chmod command applies a set-user-ID permission mode",
                    line_number=index + 1,
                ))
                break
        return findings

    def _has_explicit_non_root_sudo_user(self, remainder: str) -> bool:
        try:
            tokens = shlex.split(remainder, posix=True)
        except ValueError:
            return False
        index = 0
        while index < len(tokens):
            token = tokens[index]
            target = ""
            if token in {"-u", "--user"}:
                if index + 1 >= len(tokens):
                    return False
                target = tokens[index + 1]
            elif token.startswith("--user="):
                target = token.split("=", 1)[1]
            elif token.startswith("-u") and len(token) > 2:
                target = token[2:]
            elif token == "--":
                return False
            elif not token.startswith("-"):
                return False
            if target:
                if target.lower() in {"root", "#0", "0"}:
                    return False
                return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*|#[1-9][0-9]*", target))
            index += 1
        return False

    def _shell_segment_end(self, masked_line: str, command_end: int) -> int:
        separator = re.search(r"[;|&)]", masked_line[command_end:])
        return len(masked_line) if separator is None else command_end + separator.start()

    def _strip_shell_comment(self, line: str) -> str:
        in_single = False
        in_double = False
        escaped = False
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == "'" and not in_double:
                in_single = not in_single
                continue
            if char == '"' and not in_single:
                in_double = not in_double
                continue
            if (
                char == "#"
                and not in_single
                and not in_double
                and (index == 0 or line[index - 1].isspace() or line[index - 1] in ";|&(){}")
            ):
                return line[:index]
        return line

    def analyze_pkgbuild(self, pkgbuild_path: str, content: str) -> AnalysisResult:
        findings = self.analyze_content(pkgbuild_path, content, Phase.pkgbuild_static)
        is_safe = not any(f.blocks_installation for f in findings)
        msg = "Deterministic rules passed." if is_safe else "Deterministic rules failed."
        return AnalysisResult(is_safe, msg, findings)

    def analyze_install_script(self, script_path: str, content: str) -> AnalysisResult:
        findings = self.analyze_content(script_path, content, Phase.install_hook_static)
        is_safe = not any(f.blocks_installation for f in findings)
        msg = "Deterministic rules passed." if is_safe else "Deterministic rules failed."
        return AnalysisResult(is_safe, msg, findings)
