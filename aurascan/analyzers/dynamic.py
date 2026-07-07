from dataclasses import dataclass, field
from typing import List, Protocol

from aurascan.analyzers.base import BaseAnalyzer
from aurascan.core.models import AnalysisResult, Finding


@dataclass
class SandboxObservation:
    kind: str
    detail: str
    path: str = ""


@dataclass
class SandboxResult:
    observations: List[SandboxObservation] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""


class SandboxBackend(Protocol):
    name: str

    def run(self, pkgbuild_path: str) -> SandboxResult:
        ...


class DynamicSandboxAnalyzer(BaseAnalyzer):
    def analyze_package(self, pkg_path: str) -> AnalysisResult:
        return AnalysisResult(True, "Dynamic sandbox interface only; package execution is disabled.", [])

    def analyze_pkgbuild(self, pkgbuild_path: str, content: str) -> AnalysisResult:
        return AnalysisResult(True, "Dynamic sandbox interface only; PKGBUILD execution is disabled.", [])
