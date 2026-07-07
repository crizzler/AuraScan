import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

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


@dataclass
class ClamAVScanResult:
    is_clean: bool
    findings: List[Finding]
    raw_output: str
    phase: Phase
    unavailable: bool = False


class ClamAVAnalyzer(BaseAnalyzer):
    def __init__(self, database_path: Optional[str] = None):
        self.database_path = database_path

    def analyze_package(self, pkg_path: str, phase: Phase = Phase.final_package_scan, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> AnalysisResult:
        if shutil.which("clamscan") is None:
            print("[AuraScan] WARNING: clamscan not found. Skipping AV signature scan.", file=sys.stderr)
            return AnalysisResult(True, "clamscan not installed", [])

        print(f"[AuraScan] Running clamscan on {pkg_path}...", file=sys.stderr)
        try:
            args = ["clamscan", "--no-summary"]
            if self.database_path:
                args.extend(["--database", self.database_path])
            args.append(str(pkg_path))
            result = subprocess.run(args, capture_output=True, text=True, timeout=60)
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
        return AnalysisResult(True, f"Clamscan error: {result.stderr.strip()}", [])

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
        raw_output = (stdout or "") + (("\n" + stderr) if stderr else "")
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
                    evidence_snippet=line.strip(),
                    raw_output=raw_output,
                    file_hash=self._file_hash(path),
                ))
        return ClamAVScanResult(is_clean=returncode == 0, findings=findings, raw_output=raw_output, phase=phase)

    def _parse_infected_line(self, line: str, fallback_path: str) -> tuple:
        if ":" not in line:
            return fallback_path, line.replace(" FOUND", "").strip()
        filepath, rest = line.split(":", 1)
        return filepath.strip() or fallback_path, rest.replace(" FOUND", "").strip()

    def database_version(self) -> str:
        if shutil.which("freshclam") is None:
            return "unknown"
        result = subprocess.run(["freshclam", "--version"], capture_output=True, text=True, timeout=10)
        return (result.stdout or result.stderr).strip() or "unknown"

    def _file_hash(self, path: str) -> Optional[str]:
        candidate = Path(path)
        if not candidate.is_file():
            return None
        digest = hashlib.sha256()
        try:
            with candidate.open("rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
        except OSError:
            return None
        return digest.hexdigest()
