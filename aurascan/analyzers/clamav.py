import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional

from aurascan.analyzers.base import BaseAnalyzer
from aurascan.core.models import (
    AnalysisResult,
    Confidence,
    EvidenceQuality,
    Finding,
    Phase,
    Severity,
    Source,
)
from aurascan.core.text_safety import sanitize_terminal_text
from aurascan.core.trusted_tools import (
    TrustedToolError,
    capture_trusted_system_tool,
    revalidate_trusted_system_tool,
    run_bounded_trusted_tool,
)


_CLAMAV_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
}


@dataclass
class ClamAVScanResult:
    is_clean: bool
    findings: List[Finding]
    raw_output: str
    phase: Phase
    unavailable: bool = False


class ClamAVAnalyzer(BaseAnalyzer):
    def __init__(
        self,
        database_path: Optional[str] = None,
        *,
        runner: Optional[Callable] = None,
        which: Callable[[str], Optional[str]] = shutil.which,
    ):
        self.database_path = database_path
        self.runner = runner or run_bounded_trusted_tool
        self.which = which

    def analyze_package(self, pkg_path: str, phase: Phase = Phase.final_package_scan, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> AnalysisResult:
        try:
            clamscan = capture_trusted_system_tool("clamscan", which=self.which)
        except TrustedToolError:
            clamscan = None
        if clamscan is None:
            print("[AuraScan] WARNING: trusted clamscan unavailable; signature scan skipped.", file=sys.stderr)
            return AnalysisResult(True, "trusted clamscan unavailable", [])

        print("[AuraScan] Running trusted clamscan...", file=sys.stderr)
        try:
            revalidate_trusted_system_tool(clamscan)
            args = [
                clamscan.path,
                "--no-summary",
                "--infected",
                "--suppress-ok-results",
                "--follow-file-symlinks=0",
                "--follow-dir-symlinks=0",
                "--cross-fs=no",
                "--bytecode-unsigned=no",
                "--alert-exceeds-max=yes",
                "--max-files=20000",
                "--max-recursion=16",
                "--max-filesize=100M",
                "--max-scansize=100M",
            ]
            if self.database_path:
                args.extend(["--database", self.database_path])
            # Terminate option parsing before the caller-controlled path.  A
            # relative filename such as ``--remove=yes`` must remain a scan
            # target, never become a ClamAV mutation option.
            args.extend(["--", str(pkg_path)])
            result = self.runner(
                args,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=os.sep,
                env=_CLAMAV_ENV,
            )
        except (TrustedToolError, OSError):
            return AnalysisResult(True, "trusted clamscan unavailable", [])
        except subprocess.TimeoutExpired:
            finding = Finding(
                rule_id="CLAMAV-TIMEOUT",
                package_name=pkg_name,
                package_version=pkg_ver,
                phase=phase,
                source=Source.clamav,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                evidence_quality=EvidenceQuality.weak_heuristic,
                file_path=str(pkg_path),
                explanation="ClamAV scan timed out. This may be a denial of service attempt.",
                recommendation="Investigate the package contents manually.",
                blocks_installation=True,
                requires_manual_review=True,
            )
            return AnalysisResult(False, "Clamscan timed out", [finding])
        except subprocess.SubprocessError:
            return AnalysisResult(
                False,
                "Clamscan output exceeded its safety bound",
                [self._incomplete_finding(pkg_path, phase, pkg_name, pkg_ver)],
            )

        parsed = self.parse_output(
            result.returncode,
            result.stdout,
            result.stderr,
            phase=phase,
            pkg_name=pkg_name,
            pkg_ver=pkg_ver,
            fallback_path=str(pkg_path),
        )
        if parsed.findings:
            return AnalysisResult(False, "Malware detected", parsed.findings)
        if result.returncode == 0:
            return AnalysisResult(True, "Clean ClamAV scan recorded; not proof of package safety", [])
        return AnalysisResult(
            False,
            "Clamscan did not complete successfully",
            [self._incomplete_finding(pkg_path, phase, pkg_name, pkg_ver)],
        )

    def _incomplete_finding(
        self,
        pkg_path: str,
        phase: Phase,
        pkg_name: str,
        pkg_ver: str,
    ) -> Finding:
        return Finding(
            rule_id="CLAMAV-INCOMPLETE",
            package_name=pkg_name,
            package_version=pkg_ver,
            phase=phase,
            source=Source.clamav,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            evidence_quality=EvidenceQuality.weak_heuristic,
            file_path=str(pkg_path),
            explanation=(
                "The trusted ClamAV process started but did not complete a bounded scan. "
                "Its raw diagnostics were discarded."
            ),
            recommendation="Do not install until the file can be scanned completely or inspected independently.",
            blocks_installation=True,
            requires_manual_review=True,
            evidence_snippet="ClamAV inspection did not complete within its safety bounds",
        )

    def scan_source_archive(self, archive_path: str, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> AnalysisResult:
        return self.analyze_package(archive_path, Phase.source_archive_scan, pkg_name, pkg_ver)

    def scan_unpacked_source(self, source_path: str, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> AnalysisResult:
        return self.analyze_package(source_path, Phase.unpacked_source_scan, pkg_name, pkg_ver)

    def scan_generated_file(self, file_path: str, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> AnalysisResult:
        return self.analyze_package(file_path, Phase.generated_file_scan, pkg_name, pkg_ver)

    def parse_output(
        self,
        returncode: int,
        stdout: str,
        stderr: str = "",
        *,
        phase: Phase = Phase.final_package_scan,
        pkg_name: str = "unknown",
        pkg_ver: str = "unknown",
        fallback_path: str = "",
    ) -> ClamAVScanResult:
        raw_output = ""
        findings: List[Finding] = []
        if returncode == 1:
            for line in stdout.splitlines():
                if " FOUND" not in line:
                    continue
                path, signature = self._parse_infected_line(line, fallback_path)
                findings.append(Finding(
                    rule_id=f"CLAMAV-{signature}",
                    package_name=pkg_name,
                    package_version=pkg_ver,
                    phase=phase,
                    source=Source.clamav,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence_quality=EvidenceQuality.confirmed_signature,
                    file_path=path,
                    explanation=f"ClamAV detected known malware signature: {signature}",
                    recommendation="DO NOT INSTALL. This is a confirmed malware signature.",
                    blocks_installation=True,
                    requires_manual_review=False,
                    evidence_snippet="ClamAV reported a matching malware signature",
                    raw_output=None,
                    file_hash=self._file_hash(path),
                ))
        return ClamAVScanResult(is_clean=returncode == 0, findings=findings, raw_output=raw_output, phase=phase)

    def _parse_infected_line(self, line: str, fallback_path: str) -> tuple:
        if ":" not in line:
            signature = line.replace(" FOUND", "").strip()
            return fallback_path, self._safe_signature(signature)
        filepath, rest = line.split(":", 1)
        safe_path = sanitize_terminal_text(
            filepath.strip() or fallback_path,
            max_chars=1024,
            single_line=True,
        )
        return safe_path or fallback_path, self._safe_signature(
            rest.replace(" FOUND", "").strip()
        )

    def _safe_signature(self, value: str) -> str:
        candidate = str(value).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@+\-]{0,255}", candidate):
            return "unknown-signature"
        return candidate

    def database_version(self) -> str:
        try:
            freshclam = capture_trusted_system_tool("freshclam", which=self.which)
        except TrustedToolError:
            freshclam = None
        if freshclam is None:
            return "unknown"
        try:
            revalidate_trusted_system_tool(freshclam)
            result = self.runner(
                [freshclam.path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=os.sep,
                env=_CLAMAV_ENV,
            )
        except (TrustedToolError, OSError, subprocess.TimeoutExpired):
            return "unknown"
        return sanitize_terminal_text(
            result.stdout or result.stderr,
            max_chars=256,
            single_line=True,
        ) or "unknown"

    def _file_hash(self, path: str) -> Optional[str]:
        digest = hashlib.sha256()
        descriptor = -1
        try:
            descriptor = os.open(
                str(Path(path)),
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 100 * 1024 * 1024:
                return None
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                return None
        except OSError:
            return None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return digest.hexdigest()
