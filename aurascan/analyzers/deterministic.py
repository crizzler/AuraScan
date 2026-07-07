import re
from typing import List
from aurascan.analyzers.base import BaseAnalyzer
from aurascan.core.models import AnalysisResult, Finding, Phase, Source, Severity, Confidence, EvidenceQuality

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
    Rule("SYS-CHMOD-001", r"chmod\s+\+s", Severity.HIGH, "Attempted to setuid/setgid binary.", True),
    Rule("EXEC-B64-001", r"base64\s+-d[^|]*\|\s*(sh|bash)", Severity.CRITICAL, "Base64 decode piped to shell.", True),
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
    "SYS-SYSTEMD-USER-001",
    "SYS-SYSTEMD-AUTO-001",
    "SYS-SYSTEMD-UNIT-001",
    "SYS-CRON-REBOOT-001",
    "SYS-CRONTAB-001",
    "SYS-CRON-FILE-001",
}

class DeterministicAnalyzer(BaseAnalyzer):
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
                        evidence_snippet=evidence_line.strip(),
                        line_number=i+1
                    )
                    findings.append(finding)
        return findings

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
            if char == "#" and not in_single and not in_double:
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
