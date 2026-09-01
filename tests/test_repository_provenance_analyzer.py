from pathlib import Path

import pytest

from aurascan.analyzers.repository_provenance import (
    RepositoryProvenanceAnalyzer,
    _scoped_commands,
    collect_required_repository_paths,
)
from aurascan.core.install_hook import (
    INSTALL_HOOK_NONE,
    INSTALL_HOOK_RESOLVED,
    InstallHookResolution,
    capture_package_scan_input,
)
from aurascan.core.models import Phase, Severity
from aurascan.core.repository_provenance import (
    REPOSITORY_COMPLETE,
    REPOSITORY_UNINSPECTED,
    RepositoryArtifact,
    RepositorySnapshot,
    capture_repository_snapshot,
)


NO_HOOK = InstallHookResolution(
    status=INSTALL_HOOK_NONE,
    declared=False,
    legacy=False,
)


def artifact(
    relative_path="payload",
    *,
    kind="elf",
    digest="a" * 64,
    mode=0o644,
    generated_output=False,
):
    return RepositoryArtifact(
        relative_path=relative_path,
        kind=kind,
        sha256=digest,
        size=64,
        mode=mode,
        generated_output=generated_output,
    )


def snapshot(*artifacts, status=REPOSITORY_COMPLETE, error_code=""):
    return RepositorySnapshot(
        status=status,
        input_digest="b" * 64,
        artifacts=tuple(artifacts),
        error_code=error_code,
        entry_count=len(artifacts),
    )


def analyze(
    content,
    *artifacts,
    hook=NO_HOOK,
    status=REPOSITORY_COMPLETE,
    error_code="",
):
    return RepositoryProvenanceAnalyzer().analyze_scan_input(
        "/tmp/fixture-package/PKGBUILD",
        content,
        hook,
        snapshot(*artifacts, status=status, error_code=error_code),
        pkg_name="fixture-package",
        pkg_ver="1.0",
    )


def finding(result, rule_id):
    return next(item for item in result.findings if item.rule_id == rule_id)


def rule_ids(result):
    return {item.rule_id for item in result.findings}


def test_undeclared_opaque_checkout_artifact_is_manual_review_presence_only():
    result = analyze("pkgname=fixture-package\npkgver=1\n", artifact())

    present = finding(result, "AUR-REPO-OPAQUE-ARTIFACT-001")
    assert result.is_safe is True
    assert present.severity == Severity.MEDIUM
    assert present.blocks_installation is False
    assert present.requires_manual_review is True
    assert present.file_path == "/tmp/fixture-package/payload"
    assert present.line_number is None
    assert present.file_hash == "a" * 64
    assert present.evidence_snippet == (
        "opaque artifact is present alongside the package checkout"
    )
    assert "committed" not in present.explanation.lower()
    assert "does not prove" in present.false_positive_notes.lower()


@pytest.mark.parametrize(
    "command",
    (
        'install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'cp "${startdir}/payload" "$pkgdir/usr/bin/payload"',
        'command install -D -m 755 "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'env -i cp "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'sudo -u root install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'install -Dm755 -t "$pkgdir/usr/bin" "$startdir/payload"',
        'install -Dm755 -t"$pkgdir/usr/bin" "$startdir/payload"',
    ),
)
def test_exact_checkout_artifact_transfer_to_pkgdir_requires_high_review(command):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
        artifact(),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert result.is_safe is True
    assert installed.severity == Severity.HIGH
    assert installed.blocks_installation is False
    assert installed.requires_manual_review is True
    assert installed.phase == Phase.pkgbuild_static
    assert installed.line_number == 3
    assert installed.file_hash == "a" * 64
    assert "/usr/bin/payload" not in installed.evidence_snippet
    assert "$startdir" not in installed.evidence_snippet
    assert "fixture-package" not in installed.evidence_snippet
    assert "AUR-REPO-OPAQUE-ARTIFACT-001" not in rule_ids(result)


@pytest.mark.parametrize(
    "redirection",
    (
        '> "$pkgdir/usr/bin/payload"',
        '>"$pkgdir/usr/bin/payload"',
    ),
)
def test_exact_cat_stdout_transfer_to_pkgdir_requires_high_review(redirection):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        f'  cat -- "$startdir/payload" {redirection}\n'
        "}\n",
        artifact(),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert result.is_safe is True
    assert installed.severity == Severity.HIGH
    assert installed.line_number == 3


def test_exact_cat_transfer_then_declared_hook_execution_is_critical():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() {\n  /usr/bin/payload --fixture\n}\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  cat "$startdir/payload" > "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.phase == Phase.install_hook_static
    assert executed.line_number == 2


@pytest.mark.parametrize(
    "command",
    (
        'cat "$startdir/payload" 2> "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" >> "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" >| "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" ">" "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" \\> "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" | tee "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" "$startdir/second" > "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" > /tmp/payload',
        'cat > "$pkgdir/usr/bin/payload"',
    ),
)
def test_nonexact_cat_forms_do_not_invent_package_transfer(command):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_cat_text_in_quoted_documentation_does_not_correlate():
    result = analyze(
        "pkgname=fixture-package\n"
        'printf "%s\\n" \'cat "$startdir/payload" > "$pkgdir/usr/bin/payload"\'\n',
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize(
    "command",
    (
        'cat "$startdir/$artifact_name" > "$pkgdir/usr/bin/payload"',
        'cat "$startdir/payload" > "$pkgdir/usr/bin/$artifact_name"',
    ),
)
def test_ambiguous_cat_artifact_or_pkgdir_destination_fails_closed(command):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


def test_transfer_supports_nested_artifact_and_recursive_simple_constants():
    result = analyze(
        "pkgname=fixture-package\n"
        "checkout_root=$startdir\n"
        'opaque_path="$checkout_root/bin/tool"\n'
        'payload_root="$pkgdir/usr/lib/fixture"\n'
        "package() {\n"
        '  install -Dm755 "$opaque_path" "$payload_root/tool"\n'
        "}\n",
        artifact("bin/tool", kind="macho"),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert installed.line_number == 6
    assert installed.severity == Severity.HIGH


@pytest.mark.parametrize(
    "copy_option",
    ("-R", "-r", "--recursive", "-a", "--archive", "-vR"),
)
def test_recursive_directory_transfer_maps_nested_artifact_to_pkgdir(copy_option):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        f'  cp {copy_option} "$startdir/bundle" '
        '"$pkgdir/usr/share/fixture-bundle"\n'
        "}\n",
        artifact("bundle/node_modules/payload"),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert installed.severity == Severity.HIGH
    assert installed.line_number == 3


def test_recursive_directory_transfer_then_exact_hook_execution_is_critical():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content=(
            "post_install() {\n"
            "  /usr/share/fixture-bundle/node_modules/payload --fixture\n"
            "}\n"
        ),
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  cp -R -T "$startdir/bundle" "$pkgdir/usr/share/fixture-bundle"\n'
        "}\n",
        artifact("bundle/node_modules/payload"),
        hook=hook,
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.phase == Phase.install_hook_static
    assert executed.line_number == 2


def test_recursive_directory_unknown_destination_shape_does_not_invent_hook_path():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content=(
            "post_install() {\n"
            "  /usr/share/fixture-bundle/node_modules/payload --fixture\n"
            "}\n"
        ),
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  cp -R "$startdir/bundle" "$pkgdir/usr/share/fixture-bundle"\n'
        "}\n",
        artifact("bundle/node_modules/payload"),
        hook=hook,
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    "removal",
    (
        'rmdir "$pkgdir/usr/bin/demo"',
        'rm -rf "$pkgdir/usr/bin/demo"',
    ),
)
def test_removed_known_directory_does_not_invent_descendant_hook_mapping(removal):
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() { /usr/bin/demo/payload --fixture; }\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  mkdir -p "$pkgdir/usr/bin/demo"\n'
        f"  {removal}\n"
        '  cp "$startdir/payload" "$pkgdir/usr/bin/demo"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    "removal",
    (
        'rm "$pkgdir/usr/bin/payload"',
        'rm -rf "$pkgdir/usr/bin"',
        'mv "$pkgdir/usr/bin" "$pkgdir/usr/retired-bin"',
    ),
)
def test_later_payload_removal_invalidates_hook_execution_mapping(removal):
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() { /usr/bin/payload --fixture; }\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        f"  {removal}\n"
        "}\n",
        artifact(),
        hook=hook,
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    "overwrite",
    (
        'printf "%s" benign > "$pkgdir/usr/bin/payload"',
        'truncate -s 0 "$pkgdir/usr/bin/payload"',
        'cp "$startdir/benign" "$pkgdir/usr/bin/payload"',
        'install -m755 "$startdir/benign" "$pkgdir/usr/bin/payload"',
        'dd if=/dev/null of="$pkgdir/usr/bin/payload"',
        'cp -rT "$startdir/benign-tree" "$pkgdir/usr/bin"',
    ),
)
def test_later_staged_overwrite_invalidates_hook_execution_mapping(overwrite):
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() { /usr/bin/payload --fixture; }\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        f"  {overwrite}\n"
        "}\n",
        artifact(),
        hook=hook,
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_later_same_artifact_overwrite_preserves_hook_execution_mapping():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() { /usr/bin/payload --fixture; }\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        '  cp "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_ambiguous_later_staged_overwrite_withholds_hook_execution_mapping():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() { /usr/bin/payload --fixture; }\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        '  cp "$startdir/benign" "$pkgdir/usr/bin/$replacement"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    "content",
    (
        "install_payload() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n"
        "package() {\n"
        "  install_payload\n"
        '  rm "$pkgdir/usr/bin/payload"\n'
        "}\n",
        "remove_payload() {\n"
        '  rm "$pkgdir/usr/bin/payload"\n'
        "}\n"
        "package() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "  remove_payload\n"
        "}\n",
    ),
)
def test_helper_and_caller_removals_invalidate_hook_mapping(content):
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() { /usr/bin/payload --fixture; }\n",
    )
    result = analyze(content, artifact(), hook=hook)

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_recursive_transfer_into_known_directory_maps_source_basename():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content=(
            "post_install() {\n"
            "  /usr/share/bundle/node_modules/payload --fixture\n"
            "}\n"
        ),
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -d "$pkgdir/usr/share"\n'
        '  cp -a "$startdir/bundle" "$pkgdir/usr/share"\n'
        "}\n",
        artifact("bundle/node_modules/payload"),
        hook=hook,
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.phase == Phase.install_hook_static


def test_nonrecursive_directory_spelling_does_not_match_nested_artifact():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  cp "$startdir/bundle" "$pkgdir/usr/share/fixture-bundle"\n'
        "}\n",
        artifact("bundle/node_modules/payload"),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_directory_move_maps_nested_artifact_to_pkgdir():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  mv "$startdir/bundle" "$pkgdir/usr/share/fixture-bundle"\n'
        "}\n",
        artifact("bundle/node_modules/payload"),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    "function_body",
    (
        "package() {\n"
        "  checkout_root=$startdir\n"
        '  opaque_path="$checkout_root/bin/tool"\n'
        '  install -Dm755 "$opaque_path" "$pkgdir/usr/bin/tool"\n'
        "}\n",
        "package() { checkout_root=$startdir; "
        "opaque_path=$checkout_root/bin/tool; "
        'install -Dm755 "$opaque_path" "$pkgdir/usr/bin/tool"; }\n',
    ),
)
def test_transfer_resolves_sequential_constants_inside_one_function(function_body):
    result = analyze(
        "pkgname=fixture-package\n" + function_body,
        artifact("bin/tool"),
    )

    assert "AUR-REPO-OPAQUE-BINARY-001" in rule_ids(result)


@pytest.mark.parametrize(
    "function_text",
    (
        "package() {\n"
        '  install -Dm755 "$opaque_path" "$pkgdir/usr/bin/tool"\n'
        '  opaque_path="$startdir/bin/tool"\n'
        "}\n",
        "prepare() { opaque_path=$startdir/bin/tool; }\n"
        "package() { "
        'install -Dm755 "$opaque_path" "$pkgdir/usr/bin/tool"; }\n',
    ),
)
def test_constants_do_not_flow_backward_or_between_functions(function_text):
    result = analyze(
        "pkgname=fixture-package\n" + function_text,
        artifact("bin/tool"),
    )

    assert "AUR-REPO-OPAQUE-BINARY-001" not in rule_ids(result)
    assert "AUR-REPO-OPAQUE-BINARY-EXEC-001" not in rule_ids(result)


@pytest.mark.parametrize(
    "command",
    (
        '"$startdir/payload" --fixture',
        "/tmp/fixture-package/payload --fixture",
        'command "$startdir/payload"',
        'command -- "$startdir/payload"',
        'env -i "$startdir/payload"',
        'sudo -- "$startdir/payload"',
        'python3 "$startdir/payload"',
        'bash -O extglob "$startdir/payload"',
        'bash -c \'"$startdir/payload" --fixture\'',
        'eval \'"$startdir/payload" --fixture\'',
    ),
)
def test_direct_execution_of_exact_checkout_artifact_is_critical(command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  " + command + "\n}\n",
        artifact(kind="pe"),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.severity == Severity.CRITICAL
    assert executed.blocks_installation is True
    assert executed.requires_manual_review is False
    assert executed.phase == Phase.pkgbuild_static
    assert executed.line_number == 3
    assert "payload" not in executed.evidence_snippet


@pytest.mark.parametrize(
    "command",
    (
        'timeout 1 "$startdir/payload"',
        'nice -n 10 "$startdir/payload"',
        'ionice -c 3 "$startdir/payload"',
        'stdbuf -o0 "$startdir/payload"',
        'chrt --other 0 "$startdir/payload"',
        'taskset 0x1 "$startdir/payload"',
        'setarch linux64 -R "$startdir/payload"',
        'prlimit --nofile=1024:1024 -- "$startdir/payload"',
        'chroot / "$startdir/payload"',
        'runuser -u nobody -- "$startdir/payload"',
        'time "$startdir/payload"',
        'time -p "$startdir/payload"',
        'env -S "$startdir/payload --fixture"',
        'env --split-string="$startdir/payload --fixture"',
    ),
)
def test_standard_execution_wrappers_preserve_exact_artifact_execution(command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  " + command + "\n}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.severity == Severity.CRITICAL
    assert executed.line_number == 3


@pytest.mark.parametrize(
    "command",
    (
        'timeout --signal "$startdir/payload" 1 /usr/bin/true',
        'nice --adjustment "$startdir/payload" /usr/bin/true',
        'ionice --class "$startdir/payload" /usr/bin/true',
        'stdbuf --output "$startdir/payload" /usr/bin/true',
        'chrt --sched-runtime "$startdir/payload" 0 /usr/bin/true',
        'prlimit --output "$startdir/payload" /usr/bin/true',
        'chroot --userspec "$startdir/payload" / /usr/bin/true',
        'runuser --group "$startdir/payload" -u nobody -- /usr/bin/true',
        '/usr/bin/time -o "$startdir/payload" /usr/bin/true',
        '/usr/bin/time -f "$startdir/payload" /usr/bin/true',
        '/usr/bin/time --output="$startdir/payload" /usr/bin/true',
        'env -a "$startdir/payload" /usr/bin/true',
        'env --argv0="$startdir/payload" /usr/bin/true',
    ),
)
def test_wrapper_option_operands_are_not_mislabeled_as_executed(command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  " + command + "\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize("lookup_option", ("-v", "-V"))
def test_command_lookup_does_not_claim_artifact_execution_or_required_capture(
    lookup_option,
):
    content = (
        "pkgname=fixture-package\nprepare() {\n"
        f'  command {lookup_option} "$startdir/payload"\n'
        "}\n"
    )
    result = analyze(content, artifact())
    required = collect_required_repository_paths(
        (content,),
        Path("/tmp/fixture-package"),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}
    assert required.paths == ()
    assert required.complete is True


@pytest.mark.parametrize(
    "command",
    (
        'env -S "$runner"',
        'env --split-string="$runner"',
        'env -S "unterminated',
    ),
)
def test_dynamic_or_malformed_env_split_string_fails_closed(command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  " + command + "\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


def test_ambiguous_wrapper_syntax_with_exact_artifact_fails_closed():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  timeout --signal "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


@pytest.mark.parametrize(
    "command",
    (
        'exec -a fixture "$startdir/payload"',
        'exec -c -l -a fixture "$startdir/payload"',
    ),
)
def test_shell_exec_options_preserve_exact_artifact_execution(command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  " + command + "\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_shell_exec_argv0_operand_is_not_mislabeled_as_execution():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  exec -a "$startdir/payload" /usr/bin/true\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize(
    "command",
    (
        'xargs "$startdir/payload" </dev/null',
        'find . -maxdepth 0 -execdir "$startdir/payload" {} +',
        'parallel "$startdir/payload" ::: fixture',
        'watch -x "$startdir/payload"',
    ),
)
def test_standard_command_consumers_preserve_exact_execution(command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  " + command + "\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


@pytest.mark.parametrize(
    "command",
    (
        'xargs --arg-file "$startdir/payload" /usr/bin/true',
        'find "$startdir/payload" -maxdepth 0 -exec /usr/bin/true {} +',
        'parallel --joblog "$startdir/payload" /usr/bin/true ::: fixture',
        'watch --interval "$startdir/payload" -x /usr/bin/true',
    ),
)
def test_command_consumer_data_operands_are_not_mislabeled_as_execution(command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  " + command + "\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_ambiguous_command_consumer_with_exact_artifact_fails_closed():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  find . -exec "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


@pytest.mark.parametrize("condition", ("DEBUG", "RETURN"))
def test_literal_debug_or_return_trap_executes_exact_artifact(condition):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        f'  trap \'"$startdir/payload" --fixture\' {condition}\n'
        "  true\n"
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.line_number == 3


@pytest.mark.parametrize(
    "trap_command",
    (
        'trap \'"$startdir/payload" --fixture\' TERM',
        "trap - DEBUG",
        "trap '' RETURN",
    ),
)
def test_signal_only_or_cleared_trap_does_not_claim_execution(trap_command):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  "
        + trap_command
        + "\n  true\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_trap_text_in_documentation_does_not_claim_execution():
    result = analyze(
        "pkgname=fixture-package\n"
        'pkgdesc="trap \'$startdir/payload\' DEBUG"\n',
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize("loader_name", ("LD_PRELOAD", "LD_AUDIT"))
def test_exported_exact_loader_artifact_then_external_command_is_critical(
    loader_name,
):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        f'  export {loader_name}="$startdir/payload"\n'
        "  /usr/bin/true\n"
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.severity == Severity.CRITICAL
    assert executed.line_number == 4


def test_exported_loader_reaches_external_command_in_literal_eval():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  export LD_PRELOAD="$startdir/payload"\n'
        "  eval '/usr/bin/true'\n"
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.line_number == 4


@pytest.mark.parametrize(
    "body",
    (
        'LD_PRELOAD="$startdir/payload"\n  /usr/bin/true',
        'export LD_PRELOAD="$startdir/payload"\n  true',
        'export LD_PRELOAD="$startdir/payload"\n  printf "%s\\n" fixture',
        'export LD_PRELOAD="$startdir/payload"\n  unset LD_PRELOAD\n  /usr/bin/true',
        'export LD_PRELOAD="$startdir/payload"\n'
        '  LD_PRELOAD=/usr/lib/fixture.so\n  /usr/bin/true',
        'export LD_PRELOAD="$startdir/payload"\n'
        '  export -n LD_PRELOAD\n  /usr/bin/true',
    ),
)
def test_builtin_unset_unexport_or_overwritten_loader_does_not_correlate(body):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n  "
        + body
        + "\n}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_function_local_exported_loader_does_not_leak_between_functions():
    result = analyze(
        "pkgname=fixture-package\n"
        "prepare() {\n"
        '  export LD_PRELOAD="$startdir/payload"\n'
        "}\n"
        "package() {\n"
        "  /usr/bin/true\n"
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_ambiguous_exported_loader_with_external_command_fails_closed():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  export LD_PRELOAD="$startdir/$loader_name"\n'
        "  /usr/bin/true\n"
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


def test_exported_loader_text_in_documentation_does_not_correlate():
    result = analyze(
        "pkgname=fixture-package\n"
        'pkgdesc="export LD_PRELOAD=$startdir/payload; /usr/bin/true"\n',
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_installed_destination_execution_in_declared_hook_is_critical():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content=(
            "post_install() {\n"
            "  /usr/bin/payload --fixture\n"
            "}\n"
        ),
    )
    result = analyze(
        "pkgname=fixture-package\n"
        "install=fixture.install\n"
        "package() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.phase == Phase.install_hook_static
    assert executed.file_path == "/tmp/fixture-package/fixture.install"
    assert executed.line_number == 2
    assert "AUR-REPO-OPAQUE-BINARY-001" not in rule_ids(result)


@pytest.mark.parametrize(
    "body",
    (
        "prepare() { /usr/bin/payload --fixture; }\n"
        "package() { install -Dm755 \"$startdir/payload\" "
        '"$pkgdir/usr/bin/payload"; }',
        "package() { /usr/bin/payload --fixture; "
        "install -Dm755 \"$startdir/payload\" "
        '"$pkgdir/usr/bin/payload"; }',
        "package() { install -Dm755 \"$startdir/payload\" "
        '"$pkgdir/usr/bin/payload"; /usr/bin/payload --fixture; }',
        "package() { \"$pkgdir/usr/bin/payload\" --fixture; "
        "install -Dm755 \"$startdir/payload\" "
        '"$pkgdir/usr/bin/payload"; }',
    ),
)
def test_host_or_not_yet_staged_execution_does_not_invent_critical(body):
    result = analyze("pkgname=fixture-package\n" + body + "\n", artifact())

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_staged_pkgdir_execution_after_transfer_is_critical():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        '  "$pkgdir/usr/bin/payload" --fixture\n'
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.line_number == 4


def test_host_chmod_does_not_apply_setid_to_staged_artifact():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "  chmod u+s /usr/bin/payload\n"
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_pkgdir_chmod_after_transfer_applies_setid_to_staged_artifact():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        '  chmod u+s "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


@pytest.mark.parametrize(
    "mode_option",
    (
        "-m 4755",
        "-m 04755",
        "-m 2755",
        "-m 02755",
        "-m 6755",
        "-m 06755",
        "-m 3755",
        "-m 5755",
        "-m 7755",
        "-m4755",
        "-Dm2755",
        "--mode=6755",
    ),
)
def test_exact_setid_install_mode_is_critical(mode_option):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        f'  install -D {mode_option} "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.severity == Severity.CRITICAL
    assert executed.line_number == 3
    assert "set-user-ID or set-group-ID" in executed.evidence_snippet


@pytest.mark.parametrize(
    "command",
    (
        'cp -a "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'cp -p "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'cp --archive "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'cp --preserve "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'cp --preserve=mode "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'cp --preserve=ownership,mode "$startdir/payload" '
        '"$pkgdir/usr/bin/payload"',
        'ln "$startdir/payload" "$pkgdir/usr/bin/payload"',
        'mv "$startdir/payload" "$pkgdir/usr/bin/payload"',
    ),
)
@pytest.mark.parametrize("mode", (0o4755, 0o2755))
def test_mode_preserving_transfer_of_setid_artifact_is_critical(command, mode):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
        artifact(mode=mode),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.severity == Severity.CRITICAL
    assert "root" not in executed.evidence_snippet.lower()


@pytest.mark.parametrize(
    ("command", "mode"),
    (
        ('cp -a "$startdir/payload" "$pkgdir/usr/bin/payload"', 0o755),
        ('cp "$startdir/payload" "$pkgdir/usr/bin/payload"', 0o4755),
        (
            'cp -a --no-preserve=mode "$startdir/payload" '
            '"$pkgdir/usr/bin/payload"',
            0o4755,
        ),
    ),
)
def test_transfer_without_proven_preserved_setid_mode_remains_high(command, mode):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
        artifact(mode=mode),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_cp_attributes_only_does_not_establish_artifact_content_transfer():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  cp --attributes-only "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(mode=0o4755),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize(
    ("command", "relative_path", "kind"),
    (
        (
            'dd if="$startdir/payload" of="$pkgdir/usr/bin/payload"',
            "payload",
            "elf",
        ),
        (
            'ln "$startdir/payload" "$pkgdir/usr/bin/payload"',
            "payload",
            "elf",
        ),
        (
            'rsync -a "$startdir/payload" "$pkgdir/usr/bin/payload"',
            "payload",
            "elf",
        ),
        (
            'tar -xf "$startdir/payload.tar" -C "$pkgdir/usr/bin"',
            "payload.tar",
            "tar",
        ),
        (
            'bsdtar --extract --file="$startdir/payload.tar" '
            '--directory="$pkgdir/usr/bin"',
            "payload.tar",
            "tar",
        ),
        (
            'unzip "$startdir/payload.zip" -d "$pkgdir/usr/bin"',
            "payload.zip",
            "zip",
        ),
    ),
)
def test_exact_payload_deployment_mechanisms_require_high_review(
    command,
    relative_path,
    kind,
):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
        artifact(relative_path, kind=kind),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    ("command", "relative_path", "kind"),
    (
        (
            'dd if="$startdir/payload" of="$pkgdir/usr/bin/payload" conv=swab',
            "payload",
            "elf",
        ),
        (
            'ln -s "$startdir/payload" "$pkgdir/usr/bin/payload"',
            "payload",
            "elf",
        ),
        (
            'rsync "$startdir/payload" host.invalid:/tmp/payload',
            "payload",
            "elf",
        ),
        (
            'tar -tf "$startdir/payload.tar"',
            "payload.tar",
            "tar",
        ),
        (
            'tar -xf "$startdir/payload.tar" -C /tmp/fixture',
            "payload.tar",
            "tar",
        ),
        (
            'unzip -t "$startdir/payload.zip"',
            "payload.zip",
            "zip",
        ),
    ),
)
def test_nonexact_or_nonpkgdir_deployment_does_not_raise_high(
    command,
    relative_path,
    kind,
):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
        artifact(relative_path, kind=kind),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_execution_of_mapped_pkgdir_destination_in_pkgbuild_is_critical():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        '  "$pkgdir/usr/bin/payload" --fixture\n'
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.phase == Phase.pkgbuild_static
    assert executed.line_number == 4


@pytest.mark.parametrize("mode", ("u+s", "g+s", "ug+s", "+s", "a+s"))
def test_exact_setid_chmod_of_installed_artifact_is_critical(mode):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        f'  chmod {mode} "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.severity == Severity.CRITICAL
    assert executed.line_number == 4


@pytest.mark.parametrize("mode", ("u=rwxs,go=rx", "a+rx,u+s", "g=rxs,o=rx"))
def test_composite_setid_chmod_of_installed_artifact_is_critical(mode):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        f'  chmod {mode} "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.severity == Severity.CRITICAL
    assert executed.line_number == 4


@pytest.mark.parametrize("recursive_option", ("-R", "--recursive"))
def test_recursive_setid_chmod_of_installed_ancestor_is_critical(recursive_option):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/lib/fixture/bin/payload"\n'
        f'  chmod {recursive_option} u+s "$pkgdir/usr/lib/fixture"\n'
        "}\n",
        artifact(),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.severity == Severity.CRITICAL
    assert executed.line_number == 4


@pytest.mark.parametrize(
    "chmod_command",
    (
        'chmod -R 4755 "$pkgdir/usr/lib/unrelated"',
        'chmod --recursive 4755 "$pkgdir/usr/lib/fixture-other"',
        'chmod -R --reference="$pkgdir/usr/lib/reference" "$pkgdir/usr/lib/fixture"',
    ),
)
def test_recursive_or_reference_chmod_without_exact_installed_ancestor_stays_high(
    chmod_command,
):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/lib/fixture/payload"\n'
        f"  {chmod_command}\n"
        "}\n",
        artifact(),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert installed.severity == Severity.HIGH
    assert "AUR-REPO-OPAQUE-BINARY-EXEC-001" not in rule_ids(result)


def test_unrelated_setid_target_does_not_escalate_checkout_artifact():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        '  chmod 4755 "$pkgdir/usr/bin/unrelated"\n'
        "}\n",
        artifact(),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert installed.severity == Severity.HIGH
    assert "AUR-REPO-OPAQUE-BINARY-EXEC-001" not in rule_ids(result)


def test_declared_hook_setid_change_of_installed_artifact_is_critical():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() {\n  chmod 4755 /usr/bin/payload\n}\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.phase == Phase.install_hook_static
    assert executed.line_number == 2


def test_known_pkgdir_directory_maps_install_basename_for_hook_execution():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() {\n  /usr/bin/payload --fixture\n}\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -d "$pkgdir/usr/bin"\n'
        '  install "$startdir/payload" "$pkgdir/usr/bin"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.phase == Phase.install_hook_static
    assert executed.line_number == 2


@pytest.mark.parametrize(
    "source_line",
    (
        'source=("payload")\nsha256sums=("fixture")',
        'source=("payload::https://example.invalid/releases/tool")\nsha256sums=("fixture")',
        'source=("https://example.invalid/releases/payload")\nsha256sums=("fixture")',
    ),
)
def test_declared_local_or_cached_source_filename_is_not_repo_embedded(source_line):
    relative = "bin/tool" if "bin/tool" in source_line else "payload"
    result = analyze(
        "pkgname=fixture-package\n" + source_line + "\n"
        "package() {\n"
        f'  install -Dm755 "$startdir/{relative}" "$pkgdir/usr/bin/tool"\n'
        "}\n",
        artifact(relative),
    )

    assert result.findings == []


def test_nested_local_source_excludes_makepkg_root_filename_not_nested_artifact():
    result = analyze(
        'pkgname=fixture-package\nsource=("bin/tool")\nsha256sums=("fixture")\n'
        "package() {\n"
        '  install -Dm755 "$startdir/bin/tool" "$pkgdir/usr/bin/tool"\n'
        "}\n",
        artifact("bin/tool"),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_ambiguous_source_with_opaque_artifact_fails_closed_without_provenance_claim():
    result = analyze(
        'pkgname=fixture-package\nsource=("https://example.invalid/$(uname).tar")\n',
        artifact(),
    )

    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert result.is_safe is False
    assert incomplete.severity == Severity.HIGH
    assert incomplete.blocks_installation is True
    assert "AUR-REPO-OPAQUE-ARTIFACT-001" not in rule_ids(result)
    assert "undeclared" not in incomplete.explanation.lower()


def test_ambiguous_source_without_opaque_artifacts_adds_no_duplicate_finding():
    result = analyze(
        'pkgname=fixture-package\nsource=("https://example.invalid/$(uname).tar")\n'
    )

    assert result.is_safe is True
    assert result.findings == []


def test_incomplete_repository_snapshot_is_a_nonreviewable_blocker():
    result = analyze(
        "pkgname=fixture-package\n",
        status=REPOSITORY_UNINSPECTED,
        error_code="file_oversized",
    )

    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert result.is_safe is False
    assert incomplete.severity == Severity.HIGH
    assert incomplete.blocks_installation is True
    assert incomplete.requires_manual_review is False
    assert incomplete.evidence_snippet == (
        "bounded package-checkout inspection did not complete: file oversized"
    )
    assert "not evidence" in incomplete.false_positive_notes.lower()


def test_wrong_type_declared_vcs_root_has_stable_coverage_reason():
    result = analyze(
        "pkgname=fixture-package\n",
        status=REPOSITORY_UNINSPECTED,
        error_code="excluded_subtree_wrong_type",
    )

    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert result.is_safe is False
    assert incomplete.evidence_snippet.endswith("excluded subtree wrong type")


@pytest.mark.parametrize(
    "content",
    (
        '# install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n',
        'pkgdesc="install -Dm755 $startdir/payload $pkgdir/usr/bin/payload"\n',
        'echo \'install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\'\n',
        'docs=(install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload")\n',
        'printf "%s\\n" \'./payload\'\n',
    ),
)
def test_comments_messages_arrays_and_documentation_do_not_correlate(content):
    result = analyze("pkgname=fixture-package\n" + content, artifact())

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_path_mismatch_or_non_pkgdir_copy_stays_presence_only():
    for command in (
        'install -Dm755 "$startdir/other" "$pkgdir/usr/bin/payload"',
        'install -Dm755 "$startdir/payload" "/tmp/payload"',
        'install -Dm755 "$startdir/other" "/tmp/payload"',
    ):
        result = analyze(
            "pkgname=fixture-package\npackage() {\n  " + command + "\n}\n",
            artifact(),
        )
        assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_generated_build_output_presence_is_not_reported_as_checkout_provenance():
    result = analyze(
        "pkgname=fixture-package\n",
        artifact("src/payload", generated_output=True),
    )

    assert result.findings == []


def test_explicit_use_of_generated_looking_artifact_is_still_correlated():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/src/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact("src/payload", generated_output=True),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_relative_execution_is_not_misattributed_across_unknown_function_cwd():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        "  cd subdir\n"
        "  ./payload\n"
        "}\n",
        artifact(),
        artifact("subdir/payload", digest="c" * 64),
    )

    assert "AUR-REPO-OPAQUE-BINARY-EXEC-001" not in rule_ids(result)
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize(
    ("directory", "source", "relative_path"),
    (
        ("$startdir", "./payload", "payload"),
        ("${pkgbuilddir}/bin", "payload", "bin/payload"),
    ),
)
def test_linear_exact_checkout_cwd_anchors_relative_transfer(
    directory,
    source,
    relative_path,
):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        f'  cd "{directory}"\n'
        f'  install -Dm755 "{source}" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(relative_path, generated_output=relative_path.startswith("src/")),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert installed.line_number == 4


def test_linear_exact_checkout_cwd_anchors_relative_execution():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  cd "$startdir/bin"\n'
        "  ./payload --fixture\n"
        "}\n",
        artifact("bin/payload"),
    )

    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert result.is_safe is False
    assert executed.line_number == 4


@pytest.mark.parametrize(
    ("command", "expected_rule"),
    (
        ("./payload", "AUR-REPO-OPAQUE-BINARY-EXEC-001"),
        ("bash ./payload", "AUR-REPO-OPAQUE-BINARY-EXEC-001"),
        ('"$PWD/payload"', "AUR-REPO-INSPECTION-INCOMPLETE-001"),
        ('bash "${PWD}/payload"', "AUR-REPO-OPAQUE-BINARY-EXEC-001"),
    ),
)
def test_top_level_pkgbuild_execution_is_anchored_to_checkout(
    command,
    expected_rule,
):
    result = analyze(
        "pkgname=fixture-package\n" + command + " --fixture\n",
        artifact(),
    )

    executed = finding(result, expected_rule)
    assert result.is_safe is False
    if expected_rule == "AUR-REPO-OPAQUE-BINARY-EXEC-001":
        assert executed.line_number == 2


def test_function_and_install_hook_relative_execution_are_not_checkout_anchored():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content='./payload --fixture\nbash "$PWD/payload"\n',
    )
    result = analyze(
        "pkgname=fixture-package\n"
        'prepare() { ./payload --fixture; bash "$PWD/payload"; }\n',
        artifact(),
        hook=hook,
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_exact_checkout_cwd_collects_relative_path_below_pruned_tree():
    required = collect_required_repository_paths(
        (
            "package() {\n"
            '  cd "$startdir/src"\n'
            '  install -Dm755 ./payload "$pkgdir/usr/bin/payload"\n'
            "}\n",
        ),
        Path("/tmp/fixture-package"),
    )

    assert required.complete is True
    assert "src/payload" in required.paths


def test_required_recursive_directory_capture_reaches_high_correlation(
    tmp_path: Path,
):
    content = (
        "pkgname=fixture-package\npackage() {\n"
        '  cp -R "$startdir/bundle" "$pkgdir/usr/share/fixture-bundle"\n'
        "}\n"
    )
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(content, encoding="utf-8")
    hidden = tmp_path / "bundle" / "node_modules"
    hidden.mkdir(parents=True)
    hidden.joinpath("payload").write_bytes(b"\x7fELF" + b"R" * 64)
    required = collect_required_repository_paths((content,), tmp_path)

    repository_snapshot = capture_repository_snapshot(
        tmp_path,
        independently_bound_relative_paths=("PKGBUILD",),
        required_relative_paths=required.paths,
        required_paths_complete=required.complete,
    )
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        content,
        NO_HOOK,
        repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1.0",
    )

    assert required.paths == ("bundle",)
    assert [
        item.relative_path for item in repository_snapshot.artifacts
    ] == ["bundle/node_modules/payload"]
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    "mutation",
    (
        "trap 'pkgver=2' DEBUG\n",
        "mutate() { pkgver=2; }\nmutate\n",
    ),
)
def test_dynamic_scalar_mutation_cannot_hide_required_opaque_artifact(
    tmp_path: Path,
    mutation: str,
):
    content = (
        "pkgname=fixture-package\n"
        "pkgver=1\n"
        + mutation
        + 'source=("https://example.invalid/foo-$pkgver")\n'
        + 'sha256sums=("fixture")\n'
        + "package() {\n"
        + '  install -Dm755 "$startdir/foo-1" "$pkgdir/usr/bin/demo"\n'
        + "}\n"
    )
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(content, encoding="utf-8")
    tmp_path.joinpath("foo-1").write_bytes(b"\x7fELF" + b"S" * 64)

    captured = capture_package_scan_input(pkgbuild)
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        captured.pkgbuild_content,
        captured.install_hook,
        captured.repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1",
    )

    assert [
        item.relative_path for item in captured.repository_snapshot.artifacts
    ] == ["foo-1"]
    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


def test_unquoted_source_extglob_cannot_hide_checkout_artifact(tmp_path: Path):
    content = (
        "pkgname=fixture-package\n"
        "source=(@(payload))\n"
        'sha256sums=("fixture")\n'
    )
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(content, encoding="utf-8")
    tmp_path.joinpath("payload").write_bytes(b"\x7fELF" + b"E" * 64)

    captured = capture_package_scan_input(pkgbuild)
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        captured.pkgbuild_content,
        captured.install_hook,
        captured.repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1",
    )

    assert [
        item.relative_path for item in captured.repository_snapshot.artifacts
    ] == ["payload"]
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize(
    "helper_body",
    (
        '  "$1"\n',
        '  bash "$1"\n',
        '  local target="$1"\n  "$target"\n',
    ),
)
def test_reachable_helper_propagates_exact_artifact_positional(helper_body):
    result = analyze(
        "run_payload() {\n"
        + helper_body
        + "}\n"
        + "prepare() {\n"
        + '  run_payload "$startdir/payload"\n'
        + "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_unused_helper_execution_and_transfer_remain_presence_only():
    result = analyze(
        "unused_exec() {\n"
        '  "$startdir/payload"\n'
        "}\n"
        "unused_install() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n"
        "prepare() {\n"
        "  :\n"
        "}\n",
        artifact(),
    )

    assert result.is_safe is True
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_reachable_helper_transfer_is_high_manual_review():
    result = analyze(
        "install_payload() {\n"
        '  install -Dm755 "$1" "$pkgdir/usr/bin/payload"\n'
        "}\n"
        "package() {\n"
        '  install_payload "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is True
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_prepare_transfer_does_not_create_surviving_install_hook_payload():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content="post_install() {\n  /usr/bin/payload\n}\n",
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\nprepare() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    assert result.is_safe is True
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_reachable_package_and_install_hook_helpers_preserve_correlation():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content=(
            "run_payload() {\n  \"$1\"\n}\n"
            "post_install() {\n  run_payload /usr/bin/payload\n}\n"
        ),
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\n"
        "install_payload() {\n"
        '  install -Dm755 "$1" "$pkgdir/usr/bin/payload"\n'
        "}\npackage() {\n"
        '  install_payload "$startdir/payload"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    assert result.is_safe is False
    executed = finding(result, "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.phase == Phase.install_hook_static


def test_unused_install_hook_helper_does_not_create_execution_correlation():
    hook = InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=True,
        legacy=False,
        path=Path("/tmp/fixture-package/fixture.install"),
        content=(
            "unused_payload() {\n  /usr/bin/payload\n}\n"
            "post_install() {\n  :\n}\n"
        ),
    )
    result = analyze(
        "pkgname=fixture-package\ninstall=fixture.install\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
        hook=hook,
    )

    assert result.is_safe is True
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


@pytest.mark.parametrize(
    "content",
    (
        "install_payload() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n"
        "package() {\n"
        "  install_payload\n"
        '  "$pkgdir/usr/bin/payload"\n'
        "}\n",
        "run_payload() {\n"
        '  "$pkgdir/usr/bin/payload"\n'
        "}\n"
        "package() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "  run_payload\n"
        "}\n",
    ),
)
def test_helper_and_caller_share_temporal_install_flow(content):
    result = analyze(content, artifact())

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_helper_execution_before_caller_transfer_does_not_invert_time():
    result = analyze(
        "run_payload() {\n"
        '  "$pkgdir/usr/bin/payload"\n'
        "}\n"
        "package() {\n"
        "  run_payload\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is True
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_verify_relative_execution_is_checkout_anchored_but_prepare_is_not():
    verify = analyze("verify() {\n  ./payload\n}\n", artifact())
    prepare = analyze("prepare() {\n  ./payload\n}\n", artifact())

    assert rule_ids(verify) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}
    assert rule_ids(prepare) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_dynamic_helper_path_fails_closed_without_blanket_cc_failure():
    ambiguous = analyze(
        "run_payload() {\n  \"$1\"\n}\n"
        "prepare() {\n  run_payload \"$unknown\"\n}\n",
        artifact(),
    )
    compiler = analyze(
        "prepare() {\n  $CC -c ordinary-source.c\n}\n",
        artifact(),
    )
    compiler_with_checkout_input = analyze(
        'prepare() {\n  $CC "$startdir/payload"\n}\n',
        artifact(),
    )

    assert rule_ids(ambiguous) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}
    assert rule_ids(compiler) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}
    assert rule_ids(compiler_with_checkout_input) == {
        "AUR-REPO-OPAQUE-ARTIFACT-001"
    }


@pytest.mark.parametrize(
    "body",
    (
        'export LD_PRELOAD="$startdir/src/payload"\n  /usr/bin/true',
        'cat "$startdir/src/payload" > "$pkgdir/usr/lib/payload"',
    ),
)
def test_loader_and_cat_collect_exact_required_path_below_pruned_tree(body):
    required = collect_required_repository_paths(
        ("package() {\n  " + body + "\n}\n",),
        Path("/tmp/fixture-package"),
    )

    assert required.complete is True
    assert "src/payload" in required.paths


def test_required_discovery_follows_only_reachable_helper_with_positionals():
    reachable = collect_required_repository_paths(
        (
            "install_payload() {\n"
            '  install -Dm755 "$1" "$pkgdir/usr/bin/payload"\n'
            "}\n"
            "package() {\n"
            '  install_payload "$startdir/src/payload"\n'
            "}\n",
        ),
        Path("/tmp/fixture-package"),
    )
    unused = collect_required_repository_paths(
        (
            "install_payload() {\n"
            '  install -Dm755 "$startdir/src/payload" '
            '"$pkgdir/usr/bin/payload"\n'
            "}\n"
            "package() {\n  :\n}\n",
        ),
        Path("/tmp/fixture-package"),
    )

    assert reachable.complete is True
    assert "src/payload" in reachable.paths
    assert unused.complete is True
    assert "src/payload" not in unused.paths


def test_required_extglob_coverage_applies_only_to_reachable_helper():
    unused = collect_required_repository_paths(
        (
            "select_payload() {\n"
            '  install -Dm755 @("$startdir/src/payload") "$pkgdir/usr/bin/payload"\n'
            "}\npackage() {\n  :\n}\n",
        ),
        Path("/tmp/fixture-package"),
    )
    reachable = collect_required_repository_paths(
        (
            "select_payload() {\n"
            '  install -Dm755 @("$startdir/src/payload") "$pkgdir/usr/bin/payload"\n'
            "}\npackage() {\n  select_payload\n}\n",
        ),
        Path("/tmp/fixture-package"),
    )

    assert unused.paths == ()
    assert unused.complete is True
    assert reachable.complete is False


@pytest.mark.parametrize("prefix", ("command", "env -i", "exec"))
def test_function_bypass_prefix_does_not_inline_shell_helper(prefix):
    result = analyze(
        "run_payload() {\n"
        '  "$startdir/payload"\n'
        "}\n"
        "prepare() {\n"
        f"  {prefix} run_payload\n"
        "}\n",
        artifact(),
    )

    assert result.is_safe is True
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_time_prefix_can_dispatch_reachable_shell_helper():
    result = analyze(
        "run_payload() {\n"
        '  "$startdir/payload"\n'
        "}\n"
        "prepare() {\n"
        "  time run_payload\n"
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_top_level_helper_is_reachable_only_after_its_definition():
    before = _scoped_commands(
        "pkgname=fixture-package\n"
        "run_payload\n"
        "run_payload() {\n"
        '  "$startdir/payload"\n'
        "}\n",
        Path("/tmp/fixture-package"),
        top_level_repository_cwd=True,
    )
    after = _scoped_commands(
        "pkgname=fixture-package\n"
        "run_payload() {\n"
        '  "$startdir/payload"\n'
        "}\n"
        "run_payload\n",
        Path("/tmp/fixture-package"),
        top_level_repository_cwd=True,
    )

    assert before is not None
    assert after is not None
    assert [item.command.executable for item in before] == ["run_payload"]
    assert [item.command.executable for item in after] == [
        "run_payload",
        "$startdir/payload",
    ]


def test_undeclared_split_package_helper_is_not_a_lifecycle_root():
    result = analyze(
        "pkgname=fixture-package\n"
        "package_unused() {\n"
        '  "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is True
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize("package_name", ("foo-bar", "foo+bar", "foo.bar", "foo@bar"))
def test_declared_split_package_function_is_a_lifecycle_root(package_name):
    result = analyze(
        f"pkgname=({package_name})\n"
        f"package_{package_name}() {{\n"
        '  "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_dynamic_split_package_declaration_fails_closed():
    result = analyze(
        'pkgname=("$selected_package")\n'
        "package_fixture-package() {\n"
        '  "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


@pytest.mark.parametrize(
    "mutation",
    (
        'printf -v target "%s" "$startdir/payload"',
        'command printf -v target "%s" "$startdir/payload"',
        'builtin printf -v target "%s" "$startdir/payload"',
        "read target",
        "mapfile target",
        "readarray target",
        "declare -n target=selected",
    ),
)
def test_mutated_command_variable_fails_closed(mutation):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        f"  {mutation}\n"
        '  "$target"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


def test_static_reassignment_after_read_reestablishes_exact_value():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        "  read target\n"
        '  target="$startdir/payload"\n'
        '  "$target"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_mapfile_array_element_in_command_position_is_tainted():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        "  mapfile -t payloads\n"
        '  "${payloads[0]}"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


@pytest.mark.parametrize(
    ("path_expression", "relative_path"),
    (
        ("$srcdir/payload", "src/payload"),
        ("$srcdir/../payload", "payload"),
    ),
)
def test_srcdir_execution_projection_fails_closed_not_exact(
    path_expression,
    relative_path,
):
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        f'  "{path_expression}"\n'
        "}\n",
        artifact(relative_path, generated_output=relative_path.startswith("src/")),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


def test_srcdir_path_is_required_capture_without_a_global_coverage_failure():
    required = collect_required_repository_paths(
        (
            "pkgname=fixture-package\nprepare() {\n"
            '  "$srcdir/payload"\n'
            "}\n",
        ),
        Path("/tmp/fixture-package"),
    )

    assert required.paths == ("src/payload",)
    assert required.complete is True


def test_srcdir_reference_without_matching_checkout_artifact_remains_clear():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  install -Dm755 "$srcdir/upstream" "$pkgdir/usr/bin/upstream"\n'
        "}\n",
    )

    assert result.is_safe is True
    assert result.findings == []


def test_exported_loader_required_path_is_captured_and_blocked_end_to_end(tmp_path):
    checkout = tmp_path / "fixture-package"
    payload = checkout / "src" / "payload"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"\x7fELF" + (b"\x00" * 60))
    content = (
        "pkgname=fixture-package\nprepare() {\n"
        '  export LD_PRELOAD="$startdir/src/payload"\n'
        "  /usr/bin/true\n"
        "}\n"
    )
    required = collect_required_repository_paths((content,), checkout)
    repository_snapshot = capture_repository_snapshot(
        checkout,
        required_relative_paths=required.paths,
        required_paths_complete=required.complete,
    )

    assert repository_snapshot.status == REPOSITORY_COMPLETE
    assert [item.relative_path for item in repository_snapshot.artifacts] == [
        "src/payload"
    ]
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(checkout / "PKGBUILD"),
        content,
        NO_HOOK,
        repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1.0",
    )
    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_checkout_cwd_does_not_leak_between_functions():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  cd "$startdir"\n'
        "}\n"
        "package() {\n"
        '  install -Dm755 ./payload "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


@pytest.mark.parametrize(
    "control",
    (
        'cd "$startdir" | true',
        'if true; then cd "$startdir"; fi',
    ),
)
def test_uncertain_or_layout_dependent_cwd_fails_closed_for_relative_transfer(control):
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        f"  {control}\n"
        '  install -Dm755 ./payload "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}


def test_srcdir_cwd_does_not_match_an_unrelated_checkout_root_artifact():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  cd "$srcdir"\n'
        '  install -Dm755 ./payload "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_setid_chmod_of_checkout_copy_is_not_an_execution_blocker():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/usr/bin/payload"\n'
        '  chmod u+s "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    installed = finding(result, "AUR-REPO-OPAQUE-BINARY-001")
    assert installed.severity == Severity.HIGH


def test_srcdir_cwd_projection_is_capture_only_not_exact_identity():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  cd "$srcdir/../src"\n'
        '  install -Dm755 ./payload "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact("src/payload", generated_output=True),
    )

    assert result.is_safe is False
    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}
    assert "AUR-REPO-OPAQUE-BINARY-EXEC-001" not in rule_ids(result)


def test_install_directory_creation_does_not_invent_artifact_transfer():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -d "$startdir/payload" "$pkgdir/usr/bin"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_bare_transfer_is_not_claimed_as_exact_checkout_identity():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  mv payload "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_pkgdir_parent_escape_is_not_described_as_package_payload_install():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/payload" "$pkgdir/../tmp/payload"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}


def test_backslash_and_slash_paths_never_collapse_to_one_artifact_identity():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/dir/payload" "$pkgdir/usr/bin/payload"\n'
        "}\n",
        artifact("dir\\payload"),
    )

    assert result.findings == []


def test_archive_artifact_uses_same_presence_and_transfer_policy():
    present = analyze("pkgname=fixture-package\n", artifact("payload.zip", kind="zip"))
    installed = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  cp "$startdir/payload.zip" "$pkgdir/opt/fixture/payload.zip"\n'
        "}\n",
        artifact("payload.zip", kind="zip"),
    )

    assert rule_ids(present) == {"AUR-REPO-OPAQUE-ARTIFACT-001"}
    assert rule_ids(installed) == {"AUR-REPO-OPAQUE-BINARY-001"}


def test_multiple_artifacts_are_correlated_independently_and_deterministically():
    result = analyze(
        "pkgname=fixture-package\npackage() {\n"
        '  install -Dm755 "$startdir/tool" "$pkgdir/usr/bin/tool"\n'
        "}\n",
        artifact("unused", digest="c" * 64),
        artifact("tool", digest="d" * 64),
    )

    assert [item.rule_id for item in result.findings] == [
        "AUR-REPO-OPAQUE-BINARY-001",
        "AUR-REPO-OPAQUE-ARTIFACT-001",
    ]
    assert [item.file_hash for item in result.findings] == ["d" * 64, "c" * 64]


def test_dynamic_or_malformed_command_stream_fails_provenance_closed():
    result = analyze(
        "pkgname=fixture-package\nprintf 'unterminated\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}
    assert result.is_safe is False


def test_ambiguous_interpreter_option_on_exact_artifact_fails_closed():
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        '  python --fixture-option "$startdir/payload"\n'
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}
    assert result.is_safe is False


def test_correlation_work_is_bounded_and_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "aurascan.analyzers.repository_provenance._MAX_CORRELATION_OPERATIONS",
        1,
    )
    result = analyze(
        "pkgname=fixture-package\necho one\necho two\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}
    assert finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001").evidence_snippet.endswith(
        "analysis limit"
    )


@pytest.mark.parametrize("shell_command", ("eval", "bash -c", "sh -c"))
def test_nested_literal_shell_expansion_counts_toward_analysis_bound(
    monkeypatch,
    shell_command,
):
    monkeypatch.setattr(
        "aurascan.analyzers.repository_provenance._MAX_CORRELATION_OPERATIONS",
        20,
    )
    nested = "; ".join("echo fixture" for _index in range(5))
    result = analyze(
        "pkgname=fixture-package\nprepare() {\n"
        f"  {shell_command} {nested!r}\n"
        "}\n",
        artifact(),
    )

    assert rule_ids(result) == {"AUR-REPO-INSPECTION-INCOMPLETE-001"}
    assert result.is_safe is False
    assert finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001").evidence_snippet.endswith(
        "analysis limit"
    )
