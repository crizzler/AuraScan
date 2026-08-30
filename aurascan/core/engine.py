import sys
import os
import json
from pathlib import Path
from typing import List
from aurascan.core.audit import log_audit
from aurascan.core.ai_provider import resolve_ai_config
from aurascan.analyzers.clamav import ClamAVAnalyzer
from aurascan.analyzers.ai_static import AIStaticAnalyzer
from aurascan.analyzers.dynamic import DynamicSandboxAnalyzer
from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.install_hook import (
    INSTALL_HOOK_RESOLVED,
    InstallHookResolution,
    PackageScanInputError,
    capture_package_scan_input,
)
from aurascan.core.models import (
    AnalysisResult,
    Confidence,
    EvidenceQuality,
    Finding,
    PackageMetadata,
    Phase,
    RiskSummary,
    ScanReport,
    Severity,
    Source,
)
from aurascan.core.risk import RiskEngine
from aurascan.core.cache import ScanCache
from aurascan.core.context_provider import build_scan_context_proof
from aurascan.core.local_package_db import LocalPackageDbContextProvider
from aurascan.core.package_archive import (
    PACKAGE_IDENTITY_RESOLVED,
    capture_package_identity,
)
from aurascan.core.source_acquisition import SourceFetcher, SourcePolicy
from aurascan.core.trust_diff import HistoryTrustDiffAdapter
from aurascan.core.update_policy import (
    ScanContext,
    ScanContextSource,
    UpdateFastPathAction,
    UpdateScanPolicy,
    UpdateScanState,
    decide_update_fast_path,
    normalize_context,
    normalize_context_source,
    normalize_policy,
)

class AuraScanEngine:
    def __init__(self, json_output=False, deep_static=False, offline=False, auto_key_fetch=True, keyserver=None, trusted_key_dirs=None, verbose=False, update_scan_policy="full", scan_context="unknown", scan_context_source="unknown", allow_user_asserted_update_context=False, local_package_db_root=None, version_compare=None):
        self.json_output = json_output
        self.deep_static = deep_static
        self.offline = offline
        self.auto_key_fetch = auto_key_fetch
        self.verbose = verbose
        self.update_scan_policy = normalize_policy(update_scan_policy)
        self.scan_context = normalize_context(scan_context)
        self.scan_context_source = normalize_context_source(scan_context_source)
        self.allow_user_asserted_update_context = allow_user_asserted_update_context
        self.local_package_db_root = Path(local_package_db_root) if local_package_db_root is not None else None
        self.version_compare = version_compare
        self.last_report = None
        self.last_scan_input_digest = ""
        self.last_scan_input = None
        self.scanner_version = "2.5.0"
        self.rule_version = "1.4.0"
        self.cache = ScanCache()
        self.risk_engine = RiskEngine()
        self.trust_diff_adapter = HistoryTrustDiffAdapter()
        self.analyzers = [
            DeterministicAnalyzer(),
            HistoryAnalyzer(),
            SourceMetadataAnalyzer(),
            ClamAVAnalyzer(),
            AIStaticAnalyzer(),
            DynamicSandboxAnalyzer()
        ]
        if self.deep_static:
            policy = SourcePolicy(
                offline=self.offline,
                auto_key_fetch=self.auto_key_fetch and not self.offline,
                keyserver=keyserver or "https://keys.openpgp.org",
                trusted_key_dirs=trusted_key_dirs or [],
            )
            self.analyzers.append(DeepStaticAnalyzer(source_fetcher=SourceFetcher(policy=policy)))

    def _print(self, msg: str, is_err: bool = False):
        if not self.json_output:
            print(msg, file=sys.stderr if is_err else sys.stdout)

    def scan_package(self, pkg_path: str, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> bool:
        # Built-package analyzers still consume a filesystem path independently.
        # Do not read or write their cache until all phases share one immutable,
        # no-follow archive snapshot and digest.
        pkg_name, pkg_ver = self._resolve_package_identity(pkg_path, pkg_name, pkg_ver)

        self._print(f"\n[AuraScan] --- Auditing Package: {pkg_path} ---", True)
        all_findings = []
        source_acquisition = []
        is_safe = True

        for analyzer in self.analyzers:
            result = analyzer.analyze_package(pkg_path)
            all_findings.extend(self._filter_findings_for_mode(result.findings))
            if self.deep_static:
                source_acquisition.extend(getattr(analyzer, "last_source_acquisition", []))
            if not result.is_safe:
                is_safe = False

        report = self._build_report(pkg_name, pkg_ver, all_findings, ["Scanned"], source_acquisition)
        out_dict = report.to_dict()
        self.last_report = out_dict

        if self.json_output:
            print(json.dumps(out_dict, indent=2))
        else:
            print(report.render_terminal(verbose=self.verbose))

        if report.risk_summary.blocks_installation:
            log_audit(pkg_path, [f.explanation for f in all_findings if f.blocks_installation])
            return False
        return True

    def _resolve_package_identity(self, pkg_path: str, pkg_name: str, pkg_ver: str):
        if not self._is_unknown_identity(pkg_name) and not self._is_unknown_identity(pkg_ver):
            return pkg_name, pkg_ver
        info_name, info_version = self._package_identity_from_pkginfo(pkg_path)
        file_name, file_version = self._package_identity_from_filename(pkg_path)
        resolved_name = pkg_name
        resolved_version = pkg_ver
        if self._is_unknown_identity(resolved_name):
            resolved_name = info_name or file_name or "unknown"
        if self._is_unknown_identity(resolved_version):
            resolved_version = info_version or file_version or "unknown"
        return resolved_name, resolved_version

    def _package_identity_from_pkginfo(self, pkg_path: str):
        captured = capture_package_identity(Path(pkg_path))
        if captured.status != PACKAGE_IDENTITY_RESOLVED:
            return "", ""
        return captured.name, captured.version

    def _package_identity_from_filename(self, pkg_path: str):
        filename = Path(pkg_path).name
        for suffix in (
            ".pkg.tar.zst",
            ".pkg.tar.xz",
            ".pkg.tar.gz",
            ".pkg.tar.bz2",
            ".pkg.tar.lrz",
            ".pkg.tar.lzo",
            ".pkg.tar.Z",
            ".pkg.tar",
        ):
            if filename.endswith(suffix):
                stem = filename[:-len(suffix)]
                break
        else:
            return "", ""
        parts = stem.rsplit("-", 3)
        if len(parts) != 4:
            return "", ""
        name, version, release, _arch = parts
        if not name or not version or not release:
            return "", ""
        return name, f"{version}-{release}"

    @staticmethod
    def _is_unknown_identity(value: str) -> bool:
        return not value or value == "unknown"

    def scan_pkgbuild(self, pkgbuild_path: str, pkg_name: str = "unknown", pkg_ver: str = "unknown") -> bool:
        self.last_scan_input_digest = ""
        self.last_scan_input = None
        cache_flags = self._cache_flags()
        try:
            scan_input = capture_package_scan_input(
                Path(pkgbuild_path),
                allow_legacy_install=True,
            )
        except PackageScanInputError as exc:
            if exc.code == "oversized":
                msg = "PKGBUILD exceeds maximum allowed size (5MB). Possible DoS padding attack."
                self._print(f"[AuraScan] \033[91mBLOCKED\033[0m {pkgbuild_path}", True)
                self._print(f"  -> {msg}", True)
                log_audit(pkgbuild_path, [msg])
                return False
            self._print(f"[AuraScan] Error reading a stable PKGBUILD snapshot ({exc.code}).", True)
            return False

        pkgbuild_bytes = scan_input.pkgbuild_bytes
        content = scan_input.pkgbuild_content
        install_hook = scan_input.install_hook
        scan_input_digest = scan_input.input_digest
        self.last_scan_input = scan_input
        self.last_scan_input_digest = scan_input_digest
        cache_key_parts = {
            "config_flags": cache_flags,
            "input_digest": scan_input_digest,
        }
        cached_res = None
        # A deep-static result depends on bytes acquired after this point.  Its
        # current cache identity covers only the PKGBUILD/install-hook snapshot,
        # so a moving or replaced remote source must never reuse an older clear
        # report.  Keep deep-static uncached until an immutable acquisition
        # manifest is part of the key.
        if not self.deep_static and self.scan_context != ScanContext.auto:
            cached_res = self.cache.get_cached_result(
                pkgbuild_path,
                self.scanner_version,
                self.rule_version,
                **cache_key_parts,
            )
        if cached_res:
            self.last_report = cached_res
            self._print(f"\n[AuraScan] --- Auditing PKGBUILD: {pkgbuild_path} (CACHED) ---", True)
            if self.json_output:
                print(json.dumps(cached_res, indent=2))
            else:
                print(ScanReport.from_dict(cached_res).render_terminal(verbose=self.verbose))

            risk = cached_res.get("risk_summary", {})
            is_safe = not risk.get("blocks_installation") and risk.get("action") != "BLOCKED"
            if not is_safe:
                log_audit(pkgbuild_path, [f["explanation"] for f in cached_res.get("findings", []) if f.get("blocks_installation")])
                return False
            return True

        self._print(f"\n[AuraScan] --- Auditing PKGBUILD: {pkgbuild_path} ---", True)
        all_findings = []
        source_acquisition = []
        is_safe = True
        if install_hook.declared and install_hook.status != INSTALL_HOOK_RESOLVED:
            all_findings.append(self._uninspected_install_hook_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                install_hook.declaration_line,
            ))
            is_safe = False

        update_decision = self._prepare_update_decision(
            pkgbuild_path,
            content,
            install_hook_resolution=install_hook,
        )
        if update_decision and update_decision.action == UpdateFastPathAction.skip_update_scan:
            report = self._build_report(
                pkg_name,
                pkg_ver,
                all_findings,
                ["Skipped by explicit new-only update policy"],
                [],
                fast_path_decision=update_decision.to_dict(),
            )
            report.risk_summary = self.risk_engine.evaluate(all_findings)
            report.baseline_update_policy = "not_updated_skipped_update"
            report.trusted_baseline_updated = False
            out_dict = report.to_dict()
            self.last_report = out_dict
            if self.json_output:
                print(json.dumps(out_dict, indent=2))
            else:
                print(report.render_terminal(verbose=self.verbose))
            if not self.deep_static:
                self.cache.set_cached_result(
                    pkgbuild_path,
                    self.scanner_version,
                    self.rule_version,
                    out_dict,
                    **cache_key_parts,
                )
            self._finalize_history(report.risk_summary, update_decision)
            if report.risk_summary.blocks_installation:
                log_audit(pkgbuild_path, [f.explanation for f in all_findings if f.blocks_installation])
                return False
            return True

        install_script = None
        if install_hook.declared and install_hook.inspectable:
            install_script = (install_hook.path, install_hook.content)
        for analyzer in self.analyzers:
            if self._skip_analyzer_for_decision(analyzer, update_decision):
                continue
            if isinstance(analyzer, HistoryAnalyzer):
                result = analyzer.analyze_pkgbuild(
                    pkgbuild_path,
                    content,
                    install_hook_resolution=install_hook,
                )
            else:
                result = analyzer.analyze_pkgbuild(pkgbuild_path, content)
            all_findings.extend(self._filter_findings_for_mode(result.findings))
            if install_script is not None and hasattr(analyzer, "analyze_install_script"):
                script_path, script_content = install_script
                install_result = analyzer.analyze_install_script(str(script_path), script_content)
                all_findings.extend(self._filter_findings_for_mode(install_result.findings))
                if not install_result.is_safe:
                    is_safe = False
            if self.deep_static:
                source_acquisition.extend(getattr(analyzer, "last_source_acquisition", []))
            if not result.is_safe:
                is_safe = False

        report = self._build_report(
            pkg_name,
            pkg_ver,
            all_findings,
            ["Scanned"],
            source_acquisition,
            fast_path_decision=update_decision.to_dict() if update_decision else None,
        )
        updated, baseline_policy = self._finalize_history(report.risk_summary, update_decision)
        report.trusted_baseline_updated = updated
        report.baseline_update_policy = baseline_policy
        out_dict = report.to_dict()
        self.last_report = out_dict

        if self.json_output:
            print(json.dumps(out_dict, indent=2))
        else:
            print(report.render_terminal(verbose=self.verbose))

        if not self.deep_static:
            self.cache.set_cached_result(
                pkgbuild_path,
                self.scanner_version,
                self.rule_version,
                out_dict,
                **cache_key_parts,
            )

        if report.risk_summary.blocks_installation:
            log_audit(pkgbuild_path, [f.explanation for f in all_findings if f.blocks_installation])
            return False
        return True

    def _build_report(self, pkg_name, pkg_ver, findings, messages, source_acquisition=None, fast_path_decision=None):
        report = ScanReport(
            package_metadata=PackageMetadata(name=pkg_name, version=pkg_ver),
            findings=findings,
            messages=messages,
            source_acquisition=source_acquisition or [],
            scan_policy=self.update_scan_policy.value,
            scan_context=self.scan_context.value,
            scan_context_source=self.scan_context_source.value,
            fast_path_decision=fast_path_decision,
        )
        if fast_path_decision:
            technical = fast_path_decision.get("technical_details", {})
            proof = technical.get("context_proof") or {}
            report.scan_context = proof.get("context") or report.scan_context
            report.scan_context_source = proof.get("source") or report.scan_context_source
            report.scan_context_authority = proof.get("authority")
            report.context_eligible_for_fast_path = bool(proof.get("eligible_for_fast_path"))
            report.context_proof_reasons = list(proof.get("proof_reasons", []))
            report.context_proof_errors = list(proof.get("proof_errors", []))
            report.context_user_warning = proof.get("user_warning", "")
            report.context_provider_name = proof.get("provider_name", "")
            report.context_installed_package_present = proof.get("installed_package_present")
            report.context_installed_version = proof.get("installed_version", "")
            report.context_candidate_version = proof.get("candidate_version", "")
            report.context_transaction_operation = proof.get("transaction_operation", "")
            report.previous_baseline_id = technical.get("previous_baseline_id")
            report.previous_baseline_scan_level = technical.get("previous_baseline_scan_level")
        report.risk_summary = self.risk_engine.evaluate(findings)
        return report

    def _cache_flags(self):
        ai_config = resolve_ai_config(os.environ)
        flags = {
            "deep_static": self.deep_static,
            "update_scan_policy": self.update_scan_policy.value,
            "scan_context": self.scan_context.value,
            "scan_context_source": self.scan_context_source.value,
            "allow_user_asserted_update_context": self.allow_user_asserted_update_context,
            "local_package_db_root": str(self.local_package_db_root) if self.local_package_db_root is not None else "",
            "ai_enabled": ai_config.enabled,
            "ai_ready": ai_config.ready,
        }
        if ai_config.enabled:
            flags.update({
                "ai_provider": ai_config.provider,
                "ai_model": ai_config.model,
                "ai_base_url": ai_config.base_url,
                "ai_config_error": ai_config.error,
            })
        return flags

    def _filter_findings_for_mode(self, findings):
        if self.deep_static:
            return findings
        acquisition_only_rules = {
            "SOURCE-UNSUPPORTED",
            "SOURCE-HTTP-FETCH-FAILED",
            "SOURCE-GIT-FETCH-FAILED",
            "SOURCE-GIT-UNAVAILABLE",
            "SOURCE-LOCAL-MISSING",
            "SIGNATURE-VERIFICATION-UNAVAILABLE",
            "SIGNATURE-VERIFICATION-ERROR",
            "KEY_UNAVAILABLE",
        }
        return [finding for finding in findings if finding.rule_id not in acquisition_only_rules]

    def _history_analyzer(self):
        for analyzer in self.analyzers:
            if isinstance(analyzer, HistoryAnalyzer):
                return analyzer
        return None

    def _uninspected_install_hook_finding(self, pkgbuild_path: str, pkg_name: str, pkg_ver: str, line_number):
        return Finding(
            rule_id="INSTALL-HOOK-UNINSPECTED-001",
            package_name=pkg_name,
            package_version=pkg_ver,
            phase=Phase.install_hook_static,
            source=Source.deterministic_rule,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence_quality=EvidenceQuality.confirmed_static_pattern,
            file_path=str(pkgbuild_path),
            line_number=line_number,
            evidence_snippet="declared install hook was not safely inspected",
            explanation="PKGBUILD declares an install hook, but AuraScan could not inspect it safely.",
            recommendation="Do not build or install this package until the declared hook is a local unchanged regular file that AuraScan can read.",
            false_positive_notes="This fail-closed finding does not prove that the package or hook is malicious.",
            blocks_installation=True,
            requires_manual_review=False,
        )

    def _prepare_update_decision(
        self,
        pkgbuild_path: str,
        content: str,
        install_hook_resolution: InstallHookResolution = None,
    ):
        if self.update_scan_policy == UpdateScanPolicy.full and self.scan_context == ScanContext.unknown:
            return None
        history = self._history_analyzer()
        current_snapshot = {}
        package_key = ""
        previous_snapshot = {}
        previous_accepted = {}
        if history:
            current_snapshot = history.snapshot_from_pkgbuild(
                pkgbuild_path,
                content,
                install_hook_resolution=install_hook_resolution,
            )
            package_key = history.package_key_for_snapshot(current_snapshot)
            if package_key:
                previous_snapshot = history.get_snapshot(package_key)
                previous_accepted = history.get_accepted_snapshot(package_key)

        trust_diff = None
        if previous_accepted and current_snapshot:
            trust_diff = self.trust_diff_adapter.classify(previous_accepted, current_snapshot)

        previous_manual_review = bool(previous_snapshot.get("required_manual_review")) and not bool(previous_snapshot.get("manual_review_resolved"))
        context_proof = self._build_context_proof(pkgbuild_path, content, current_snapshot, previous_accepted)
        state = UpdateScanState(
            policy=self.update_scan_policy,
            context=context_proof.context,
            context_source=context_proof.source,
            already_installed=context_proof.installed_package_present is True,
            prior_baseline_exists=bool(previous_snapshot),
            prior_baseline_accepted=bool(previous_accepted),
            previous_scan_blocked=bool(previous_snapshot.get("blocked")) or previous_snapshot.get("scan_status") == "blocked",
            previous_scan_required_manual_review=previous_manual_review or previous_snapshot.get("scan_status") == "manual_review_required",
            explicit_deep_static=self.deep_static,
            trust_diff_result=trust_diff,
            context_proof=context_proof,
        )
        decision = decide_update_fast_path(state)
        if decision.technical_details is not None:
            decision.technical_details["previous_baseline_id"] = previous_accepted.get("snapshot_id") if previous_accepted else None
            decision.technical_details["previous_baseline_scan_level"] = previous_accepted.get("scan_level") if previous_accepted else None
            decision.technical_details["package_key"] = package_key
        if decision.action == UpdateFastPathAction.use_smart_fast_path and history and package_key:
            history.pending_snapshots[package_key] = current_snapshot
        return decision

    def _build_context_proof(self, pkgbuild_path: str, content: str, current_snapshot, previous_accepted):
        if self.scan_context == ScanContext.auto:
            provider = LocalPackageDbContextProvider(
                pkgbuild_path=pkgbuild_path,
                content=content,
                metadata=current_snapshot,
                local_db_root=self.local_package_db_root,
                version_compare=self.version_compare,
            )
            return provider.build_proof()

        return build_scan_context_proof(
            context=self.scan_context,
            source=self.scan_context_source,
            allow_user_asserted_update_context=self.allow_user_asserted_update_context,
            package_name=current_snapshot.get("package_name", ""),
            package_base=current_snapshot.get("pkgbase", ""),
            installed_version=previous_accepted.get("version", "") if previous_accepted else "",
            candidate_version=current_snapshot.get("version", ""),
            transaction_operation="update" if self.scan_context == ScanContext.update else "",
            installed_package_present=bool(previous_accepted) if self.scan_context == ScanContext.update else None,
        )

    def _skip_analyzer_for_decision(self, analyzer, decision) -> bool:
        if not decision or decision.action != UpdateFastPathAction.use_smart_fast_path:
            return False
        return isinstance(analyzer, (HistoryAnalyzer, ClamAVAnalyzer, AIStaticAnalyzer, DynamicSandboxAnalyzer, DeepStaticAnalyzer))

    def _scan_level_for_decision(self, decision) -> str:
        if decision and decision.action == UpdateFastPathAction.use_smart_fast_path:
            return "smart_fast_path"
        if self.deep_static:
            return "deep_static"
        return "fast_default"

    def _finalize_history(self, risk_summary: RiskSummary, decision=None):
        updated = False
        policy = "no_pending_history"
        for analyzer in self.analyzers:
            if isinstance(analyzer, HistoryAnalyzer):
                if decision and decision.action == UpdateFastPathAction.skip_update_scan:
                    analyzer.discard_pending_snapshots()
                    return False, "not_updated_skipped_update"
                if risk_summary.blocks_installation:
                    analyzer.discard_pending_snapshots()
                    return False, "not_updated_blocked"
                if risk_summary.requires_manual_review:
                    analyzer.discard_pending_snapshots()
                    return False, "not_updated_manual_review_required"
                if analyzer.pending_snapshots:
                    trust_diff = None
                    if decision:
                        trust_diff = decision.technical_details.get("trust_boundary_diff")
                    analyzer.commit_pending_snapshots(
                        scan_level=self._scan_level_for_decision(decision),
                        scanner_version=self.scanner_version,
                        rule_version=self.rule_version,
                        trust_diff=trust_diff,
                    )
                    updated = True
                    policy = "trusted_baseline_updated"
                else:
                    policy = "no_pending_history"
        return updated, policy
