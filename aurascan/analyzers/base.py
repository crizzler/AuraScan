from aurascan.core.models import AnalysisResult

class BaseAnalyzer:
    @property
    def name(self):
        return self.__class__.__name__

    def analyze_package(self, pkg_path: str) -> AnalysisResult:
        return AnalysisResult(True, "Not applicable")

    def analyze_pkgbuild(self, pkgbuild_path: str, content: str) -> AnalysisResult:
        return AnalysisResult(True, "Not applicable")

    def analyze_install_script(self, script_path: str, content: str) -> AnalysisResult:
        return AnalysisResult(True, "Not applicable")
