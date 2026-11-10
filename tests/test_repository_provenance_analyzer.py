import re
from pathlib import Path

import pytest

from aurascan.analyzers.repository_provenance import (
    RepositoryProvenanceAnalyzer,
    _active_shell_text,
    _blank_case_arm_patterns,
    _constant_assignment_statement,
    _declared_split_package_functions,
    _function_regions,
    _MAX_SPLIT_HELPER_VISITS,
    _mask_conditional_compound_operators,
    _nameref_declaration_names,
    _resolve,
    _resolve_bounded_expansion,
    _scoped_commands,
    _static_assignment_value,
    collect_required_repository_paths,
)
from aurascan.analyzers.remote_access import mask_shell_quoted_text
from aurascan.core.install_hook import (
    INSTALL_HOOK_NONE,
    INSTALL_HOOK_RESOLVED,
    InstallHookResolution,
    capture_package_scan_input,
)
from aurascan.core.models import PackageMetadata, Phase, ScanReport, Severity
from aurascan.core.repository_provenance import (
    REPOSITORY_COMPLETE,
    REPOSITORY_UNINSPECTED,
    RepositoryArtifact,
    RepositorySnapshot,
    capture_repository_snapshot,
)
from aurascan.core.risk import RiskEngine
from aurascan.core.scan_report_presenter import render_scan_report


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


def snapshot(*artifacts, status=REPOSITORY_COMPLETE, error_code="", failure_detail=""):
    return RepositorySnapshot(
        status=status,
        input_digest="b" * 64,
        artifacts=tuple(artifacts),
        error_code=error_code,
        failure_detail=failure_detail,
        entry_count=len(artifacts),
    )


def analyze(
    content,
    *artifacts,
    hook=NO_HOOK,
    status=REPOSITORY_COMPLETE,
    error_code="",
    failure_detail="",
):
    return RepositoryProvenanceAnalyzer().analyze_scan_input(
        "/tmp/fixture-package/PKGBUILD",
        content,
        hook,
        snapshot(
            *artifacts,
            status=status,
            error_code=error_code,
            failure_detail=failure_detail,
        ),
        pkg_name="fixture-package",
        pkg_ver="1.0",
    )


def finding(result, rule_id):
    return next(item for item in result.findings if item.rule_id == rule_id)


def rule_ids(result):
    return {item.rule_id for item in result.findings}


def test_preexisting_declared_vcs_checkout_directory_is_manual_review(tmp_path: Path):
    content = (
        "pkgname=fixture-package\n"
        "pkgver=1\n"
        'source=("myproject::git+https://example.invalid/myproject.git#tag=v1.0")\n'
        'sha256sums=("SKIP")\n'
    )
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(content, encoding="utf-8")
    checkout = tmp_path / "myproject"
    checkout.mkdir()
    (checkout / "payload").write_bytes(b"\x7fELF" + b"P" * 64)

    captured = capture_package_scan_input(pkgbuild)
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        captured.pkgbuild_content,
        captured.install_hook,
        captured.repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1",
    )

    assert captured.repository_snapshot.source_owned_subtrees == ("myproject",)
    assert captured.repository_snapshot.artifacts == ()
    present = finding(result, "AUR-REPO-PREEXISTING-VCS-CHECKOUT-001")
    assert present.severity == Severity.MEDIUM
    assert present.requires_manual_review is True
    assert present.blocks_installation is False
    assert result.is_safe is True


def test_plain_name_git_checkout_reuse_is_reported(tmp_path: Path):
    content = (
        "pkgname=fixture-package\n"
        "pkgver=1\n"
        'source=("git+https://example.invalid/tools/upstream.git#tag=v1.0")\n'
        'sha256sums=("SKIP")\n'
    )
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(content, encoding="utf-8")
    (tmp_path / "upstream").mkdir()

    captured = capture_package_scan_input(pkgbuild)
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        captured.pkgbuild_content,
        captured.install_hook,
        captured.repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1",
    )

    assert captured.repository_snapshot.source_owned_subtrees == ("upstream",)
    assert "AUR-REPO-PREEXISTING-VCS-CHECKOUT-001" in rule_ids(result)


def test_absent_vcs_checkout_directory_is_silent(tmp_path: Path):
    content = (
        "pkgname=fixture-package\n"
        "pkgver=1\n"
        'source=("git+https://example.invalid/tools/upstream.git#tag=v1.0")\n'
        'sha256sums=("SKIP")\n'
    )
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(content, encoding="utf-8")

    captured = capture_package_scan_input(pkgbuild)
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        captured.pkgbuild_content,
        captured.install_hook,
        captured.repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1",
    )

    assert captured.repository_snapshot.source_owned_subtrees == ()
    assert rule_ids(result) == set()


def test_preexisting_directory_for_non_vcs_source_is_silent(tmp_path: Path):
    content = (
        "pkgname=fixture-package\n"
        "pkgver=1\n"
        'source=("renamed::https://example.invalid/x.tar.gz")\n'
        'sha256sums=("SKIP")\n'
    )
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(content, encoding="utf-8")
    (tmp_path / "renamed").mkdir()
    (tmp_path / "renamed" / "notes.txt").write_text("plain text", encoding="utf-8")

    captured = capture_package_scan_input(pkgbuild)
    result = RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        captured.pkgbuild_content,
        captured.install_hook,
        captured.repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1",
    )

    assert captured.repository_snapshot.source_owned_subtrees == ()
    assert "AUR-REPO-PREEXISTING-VCS-CHECKOUT-001" not in rule_ids(result)


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


# --- split-package reference grammar (corrected v1) -----------------------

SPLIT_DEFINITIONS = (
    "package_a() {\n  :\n}\n"
    "package_b() {\n  :\n}\n"
    "package_other() {\n  :\n}\n"
)
SHELLY_PKGBUILD = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "shelly-PKGBUILD"
)


def split_roots(text):
    """Classify the top level exactly as ``_scoped_commands`` does."""

    regions = _function_regions(mask_shell_quoted_text(_active_shell_text(text))) or []
    definitions = {region.name: region for region in regions}
    return _declared_split_package_functions(text, definitions)


def test_split_pkgname_source_reference_preserves_declared_roots():
    scalar = 'pkgname=a\nsource=("$pkgname.tar.gz")\n' + SPLIT_DEFINITIONS
    array = (
        "pkgname=('a' 'b')\n"
        'source=("${pkgname}-${pkgver}.tar.gz::https://example.invalid/x")\n'
        + SPLIT_DEFINITIONS
    )

    assert split_roots(scalar) == {"package_a"}
    assert split_roots(array) == {"package_a", "package_b"}
    assert split_roots("pkgname=a\n" + SPLIT_DEFINITIONS) == {"package_a"}
    assert split_roots("pkgname=('a' 'b')\n" + SPLIT_DEFINITIONS) == {
        "package_a",
        "package_b",
    }


def test_split_pkgname_source_reference_completes_minimal_capture():
    content = (
        "pkgname=('a' 'b')\n"
        'source=("${pkgname}-${pkgver}.tar.gz::https://example.invalid/x")\n'
        "package_a() {\n  :\n}\n"
        "package_b() {\n  :\n}\n"
    )
    required = collect_required_repository_paths(
        (content,),
        Path("/tmp/fixture-package"),
    )
    result = analyze(content, artifact())

    assert required.complete is True
    assert required.paths == ()
    assert "AUR-REPO-INSPECTION-INCOMPLETE-001" not in rule_ids(result)


def test_split_pkgname_reference_does_not_enroll_dead_helper():
    content = (
        "pkgname=('a' 'b')\n"
        'source=("${pkgname}-${pkgver}.tar.gz::https://example.invalid/x")\n'
        "package_a() {\n"
        '  "$startdir/payload"\n'
        "}\n"
        "package_b() {\n  :\n}\n"
        "package_unused() {\n"
        '  "$startdir/payload"\n'
        "}\n"
    )

    result = analyze(content, artifact())

    assert rule_ids(result) == {"AUR-REPO-OPAQUE-BINARY-EXEC-001"}


def test_split_reference_resolution_does_not_imply_capture_complete():
    content = "pkgname=('a' 'b')\n[[ $pkgname == a ]] && :\n" + SPLIT_DEFINITIONS
    required = collect_required_repository_paths(
        (content,),
        Path("/tmp/fixture-package"),
    )

    assert split_roots(content) == {"package_a", "package_b"}
    # The collector cannot classify the inline test guard; roots still resolve.
    assert required.complete is False


@pytest.mark.parametrize(
    "reference",
    (
        'echo "${pkgname:=0}"',
        'echo "${pkgname=0}"',
        'echo "${pkgname:+0}"',
        'echo "${pkgname#x}"',
        'echo "${pkgname%x}"',
        'echo "${pkgname/x/y}"',
        'echo "${pkgname:1}"',
        'echo "${pkgname[0]}"',
        'echo "${!pkgname}"',
        'echo "${pkgname@Q}"',
        'echo "${pkgname[@]}"',
        'echo "${pkgname##*/}"',
        'echo "${#pkgname}"',
        'echo "pkgname=y"',
        "echo pkgname",
    ),
)
def test_split_pkgname_unsupported_reference_fails_closed(reference):
    content = f"pkgname=a\n{reference}\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize(
    "statement",
    (
        "y=$((pkgname))",
        "a='pkgname=0'; y=$((pkgname))",
        "v='pkgname=1'; ((v))",
        "[[ (pkgname=0) -eq 0 ]]",
        "[[ $pkgname -eq 0 ]]",
        "((pkgname=1))",
        "((pkgname++))",
        "echo $((pkgname))",
        "let pkgname=1",
        "pkgname+=('x')",
        "pkgname[0]=x",
        "export pkgname=x",
        "declare pkgname=x",
        "typeset pkgname=x",
        "local pkgname=x",
        "readonly pkgname=x",
        "printf -v pkgname x",
        "printf -vpkgname x",
        "read pkgname",
        "unset pkgname",
        "mapfile -t pkgname",
        "readarray -t pkgname",
        "getopts o pkgname",
        "for pkgname in x; do :; done",
        "select pkgname in x; do :; done",
        "pkgname=x env true",
        'eval "$v=(x)"',
        'source "$f"',
        '. "$f"',
        "case $pkgname in a) : ;; esac",
        "case $x in pkgname) : ;; esac",
    ),
)
def test_split_pkgname_mutation_fails_closed(statement):
    content = f"pkgname=a\n{statement}\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize(
    "statement",
    (
        "arr[$pkgname]=x",
        "arr[${pkgname}]=x",
        'echo "${pkgname[0]}"',
        "[[ -v x[$pkgname] ]]",
        "echo $((1 + $pkgname))",
        "declare -i x=${pkgname}+0",
        "typeset -i x=${pkgname}+0",
        "readonly -i x=${pkgname}+0",
        "local -i x=${pkgname}+0",
        "x=${pkgname}+0",
        "x=$pkgname+0",
        "x=${pkgname}-suffix",
    ),
)
def test_split_pkgname_arithmetic_position_fails_closed(statement):
    content = f"pkgname=(a b)\n{statement}\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize(
    "statement",
    (
        "x=$pkgname",
        "x=${pkgname}",
        'x="${pkgname}"',
        'x="a"$pkgname',
        'source=("${pkgname}-${pkgver}.tar.gz::https://example.invalid/x")',
        "[[ $pkgname == a ]] && :",
        "[[ $pkgname == a*b ]] && :",
        "[[ $pkgname =~ ^a ]] && :",
    ),
)
def test_split_pkgname_plain_value_position_stays_inert(statement):
    content = f"pkgname=(a b)\n{statement}\n" + SPLIT_DEFINITIONS

    assert split_roots(content) == {"package_a", "package_b"}


@pytest.mark.parametrize(
    "statement",
    (
        'command eval "$v"',
        'builtin unset "$v"',
        'x=1 eval "$v"',
        'if true; then eval "$v"; fi',
        'command printf -v "$v" x',
        'builtin printf -v "$v" x',
        '! eval "$v"',
    ),
)
def test_split_pkgname_prefixed_opaque_command_fails_closed(statement):
    content = 'pkgname=a\nv="${pkgname}"\n' + statement + "\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize(
    "call",
    (
        "command mut",
        "if true; then mut; fi",
        "x=1 mut",
        "! mut",
        "while mut; do :; done",
    ),
)
def test_split_pkgname_effective_helper_call_fails_closed(call):
    content = "mut() {\n  pkgname=b\n}\npkgname=a\n" + call + "\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize("prefixes", (7, 8))
def test_split_pkgname_prefix_strip_exhaustion_fails_closed(prefixes):
    calls = "command " * prefixes + "mut"
    content = "mut() {\n  pkgname=b\n}\npkgname=a\n" + calls + "\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize("prefixes", (7, 8))
def test_split_pkgname_assignment_prefix_exhaustion_fails_closed(prefixes):
    assignments = " ".join(f"a{index}=1" for index in range(prefixes))
    content = (
        'pkgname=a\nv="${pkgname}"\n' + assignments + ' eval "$v"\n' + SPLIT_DEFINITIONS
    )

    assert split_roots(content) is None


@pytest.mark.parametrize("statement", ('x=$pkgname"x"', "x=${pkgname}-suffix"))
def test_split_pkgname_non_separator_tail_fails_closed(statement):
    content = f"pkgname=(a b)\n{statement}\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize(
    "call",
    ("command noop", "if true; then noop; fi", "x=1 noop"),
)
def test_split_pkgname_prefixed_neutral_command_is_accepted(call):
    content = "noop() {\n  :\n}\npkgname=a\n" + call + "\n" + SPLIT_DEFINITIONS

    assert split_roots(content) == {"package_a"}


@pytest.mark.parametrize(
    "write",
    (
        'unset "$v"',
        'mapfile "$v"',
        'readarray "$v"',
        'typeset "$v=zz"',
        'declare "$v=x"',
        'export "$v"=x',
        'printf -v "$v" x',
        'read "$v"',
        'getopts o "$v"',
        'declare -n ref="$v"\nref=zz',
    ),
)
def test_split_pkgname_computed_name_write_fails_closed(write):
    content = 'pkgname=a\nv="${pkgname}"\n' + write + "\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize(
    "second",
    ("pkgname=b", "pkgname=('b' 'other')"),
)
def test_split_pkgname_two_declarations_fail_closed(second):
    content = f"pkgname=a\n{second}\n" + SPLIT_DEFINITIONS

    assert split_roots(content) is None


@pytest.mark.parametrize(
    "content",
    (
        "cat <<'EOF'\npkgname=other\nEOF\n",
        "pkgname=a\ncat <<'EOF'\npkgname=other\nEOF\n",
        "pkgname=a\ncat <<'EOF'\n${pkgname}\nEOF\n",
        "pkgname=a\ncat <<-'EOF'\npkgname=other\nEOF\n",
    ),
)
def test_split_pkgname_top_level_heredoc_fails_closed(content):
    assert split_roots(content + SPLIT_DEFINITIONS) is None


def test_split_pkgname_helper_function_mutation_fails_closed():
    direct = "mut() {\n  pkgname=b\n}\npkgname=a\nmut\n" + SPLIT_DEFINITIONS
    transitive = (
        "mut() {\n  pkgname=b\n}\n"
        "outer() {\n  mut\n}\n"
        "pkgname=a\nouter\n" + SPLIT_DEFINITIONS
    )
    cycle = "x() {\n  y\n}\ny() {\n  x\n}\npkgname=a\nx\n" + SPLIT_DEFINITIONS

    assert split_roots(direct) is None
    assert split_roots(transitive) is None
    assert split_roots(cycle) is None


def test_split_pkgname_neutral_helper_is_accepted():
    content = "noop() {\n  :\n}\npkgname=a\nnoop\n" + SPLIT_DEFINITIONS

    assert split_roots(content) == {"package_a"}


def test_split_pkgname_oversize_helper_recursion_fails_closed():
    chain = "".join(f"h{index}() {{\n  h{index + 1}\n}}\n" for index in range(12))
    content = (
        "pkgname=a\n"
        + chain
        + "h12() {\n  :\n}\n"
        + "h0\n"
        + SPLIT_DEFINITIONS
    )

    assert split_roots(content) is None


def test_shelly_pkgname_reference_fix_preserves_residual_incomplete():
    content = SHELLY_PKGBUILD.read_text(encoding="utf-8")
    required = collect_required_repository_paths(
        (content,),
        Path("/tmp/fixture-package"),
    )

    assert split_roots(content) == {
        "package_shelly",
        "package_shelly-flatpak-backend",
    }
    # Independent collector/cwd layers still block complete capture.
    assert required.complete is False


def test_split_pkgname_helper_visit_limit_fails_closed():
    # Depth stays at one; only the total visit counter can refuse this.
    calls = "h\n" * (_MAX_SPLIT_HELPER_VISITS + 1)
    content = "pkgname=a\nh() {\n  :\n}\n" + calls + SPLIT_DEFINITIONS

    assert split_roots(content) is None


def _write_split_package(root: Path, extra, *, hook: bool) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    text = "pkgname=(a b)\n" + extra + "\n" + SPLIT_DEFINITIONS
    if hook:
        text = text.replace("package_a", "install=fixture.install\npackage_a", 1)
        (root / "fixture.install").write_text(
            "post_install() {\n  :\n}\n",
            encoding="utf-8",
        )
    pkgbuild = root / "PKGBUILD"
    pkgbuild.write_text(text, encoding="utf-8")
    return pkgbuild


def _captured_result(pkgbuild: Path):
    captured = capture_package_scan_input(pkgbuild)
    return RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(pkgbuild),
        captured.pkgbuild_content,
        captured.install_hook,
        captured.repository_snapshot,
        pkg_name="fixture-package",
        pkg_ver="1",
    )


@pytest.mark.parametrize("hook", (False, True))
def test_split_pkgname_incomplete_evidence_names_the_family(tmp_path: Path, hook):
    """The family must reach the finding through the real capture path."""

    pkgbuild = _write_split_package(tmp_path, "y=$((pkgname))", hook=hook)

    result = _captured_result(pkgbuild)

    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert incomplete.evidence_snippet.endswith("(arithmetic context)")
    assert incomplete.severity == Severity.HIGH
    assert incomplete.blocks_installation is True
    assert "pkgname" not in incomplete.evidence_snippet


def test_split_pkgname_family_is_bound_to_its_own_capture(tmp_path: Path):
    arithmetic = _write_split_package(tmp_path / "arithmetic", "y=$((pkgname))", hook=False)
    opaque = _write_split_package(tmp_path / "opaque", "eval x", hook=False)
    captured_arithmetic = capture_package_scan_input(arithmetic)
    captured_opaque = capture_package_scan_input(opaque)

    def evidence(captured, pkgbuild):
        result = RepositoryProvenanceAnalyzer().analyze_scan_input(
            str(pkgbuild),
            captured.pkgbuild_content,
            captured.install_hook,
            captured.repository_snapshot,
        )
        return finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001").evidence_snippet

    # Analysing a saved snapshot must not inherit the later capture's family.
    assert evidence(captured_arithmetic, arithmetic).endswith("(arithmetic context)")
    assert evidence(captured_opaque, opaque).endswith(
        "(opaque evaluation (eval/source))"
    )


def test_split_package_independent_required_path_failure_has_no_family(tmp_path: Path):
    pkgbuild = _write_split_package(tmp_path, "[[ $pkgname == a ]] && :", hook=False)
    captured = capture_package_scan_input(pkgbuild)

    assert captured.repository_snapshot.error_code == "required_path_ambiguous"
    assert captured.repository_snapshot.required_paths_family == ""
    incomplete = finding(
        _captured_result(pkgbuild),
        "AUR-REPO-INSPECTION-INCOMPLETE-001",
    )
    assert incomplete.evidence_snippet.endswith("required path ambiguous")


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


def test_incomplete_inspection_names_the_first_unsupported_entry():
    result = analyze(
        "pkgname=fixture-package\npkgver=1\n",
        status=REPOSITORY_UNINSPECTED,
        error_code="symlink_entry",
        failure_detail="linked-payload -> /media/usb/payload",
    )

    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert incomplete.user_summary == (
        "First unsupported entry: linked-payload -> /media/usb/payload "
        "(a symbolic link)."
    )
    assert incomplete.technical_details == incomplete.user_summary
    assert incomplete.file_path == "/tmp/fixture-package/PKGBUILD"
    assert result.is_safe is False


def test_incomplete_inspection_without_an_observed_entry_keeps_template_text():
    result = analyze(
        "pkgname=fixture-package\npkgver=1\n",
        status=REPOSITORY_UNINSPECTED,
        error_code="entry_limit",
    )

    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert incomplete.user_summary is None
    assert incomplete.technical_details is None


def test_incomplete_inspection_sanitizes_a_hostile_observed_entry():
    result = analyze(
        "pkgname=fixture-package\npkgver=1\n",
        status=REPOSITORY_UNINSPECTED,
        error_code="symlink_entry",
        failure_detail="entry\x1b[31mspoof",
    )

    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert "\x1b" not in incomplete.user_summary
    assert incomplete.user_summary == (
        "First unsupported entry: entryspoof (a symbolic link)."
    )


def test_incomplete_provenance_report_shows_the_unsupported_entry_by_default():
    result = analyze(
        "pkgname=fixture-package\npkgver=1\n",
        status=REPOSITORY_UNINSPECTED,
        error_code="symlink_entry",
        failure_detail="linked-payload -> /media/usb/payload",
    )
    report = ScanReport(
        PackageMetadata("fixture-package", "1.0"),
        list(result.findings),
    )
    report.risk_summary = RiskEngine().evaluate(list(result.findings))

    rendered = render_scan_report(report, use_color=False, verbose=False)

    assert "Package-repository provenance inspection did not complete." in rendered
    assert (
        "First unsupported entry: linked-payload -> /media/usb/payload "
        "(a symbolic link)."
    ) in rendered
    assert "could not obtain a bounded, stable, no-follow snapshot" not in rendered


def _control_word_package(body):
    return "pkgname=fixture-package\npackage() {\n  " + body + "\n}\n"


def _control_word_scope(body):
    return _scoped_commands(
        _control_word_package(body),
        Path("/tmp/fixture-package"),
        top_level_repository_cwd=True,
        lifecycle_kind="pkgbuild",
    )


@pytest.mark.parametrize(
    "segment, expected",
    (
        ("do lang=$", (True, {"lang": None}, set(), set())),
        ("then lang=lit", (True, {"lang": "lit"}, set(), set())),
        ("else export LANG=lit", (True, {"LANG": "lit"}, {"LANG"}, set())),
        ("while ! lang=lit", (True, {"lang": "lit"}, set(), set())),
    ),
)
def test_control_word_prefixed_assignment_is_tracked(segment, expected):
    """The single-line loop head must assign like its multi-line spelling.

    ``_iter_shell_segments`` leaves the compound keyword attached to the first
    command, and POSIX XCU 2.9.1 makes an assignment with no command name
    affect the current execution environment.
    """

    assert _constant_assignment_statement(segment, {}) == expected
    # Only a bounded number of leading keywords is accepted: a third keyword
    # keeps today's rejection instead of scanning arbitrary shell text.
    assert _constant_assignment_statement("if then else lang=lit", {}) == (
        False,
        {},
        set(),
        set(),
    )
    # A command name after the assignment position still rejects the segment.
    assert _constant_assignment_statement("do echo lang=lit", {}) == (
        False,
        {},
        set(),
        set(),
    )

    single = _control_word_scope(
        'for f in a; do lang=lit; install "$lang" "$pkgdir/y"; done'
    )
    multi = _control_word_scope(
        'for f in a; do\n    lang=lit\n    install "$lang" "$pkgdir/y"\n  done'
    )

    assert single is not None
    assert multi is not None
    single_install = [item for item in single if item.command.executable == "install"]
    multi_install = [item for item in multi if item.command.executable == "install"]
    assert len(single_install) == 1
    assert len(multi_install) == 1
    assert single_install[0].constants["lang"] == "lit"
    assert single_install[0].constants == multi_install[0].constants


def test_stale_constant_not_carried_past_control_word_assignment():
    """A dropped control-word assignment must never leave a stale constant.

    Previously the single-line form resolved ``$lang`` from an older
    assignment and the collector fabricated ``d/old`` with ``complete=True``.
    """

    single = _control_word_scope(
        'lang=old\n  for f in a; do lang=lit; install "d/$lang" x; done'
    )
    multi = _control_word_scope(
        'lang=old\n  for f in a; do\n    lang=lit\n    install "d/$lang" x\n  done'
    )

    assert single is not None
    assert multi is not None
    # The ``for`` head still reflects the value in effect before the body ran;
    # everything after the control-word assignment must not see the old value.
    assert all(
        item.constants.get("lang") != "old"
        for item in single
        if item.command.executable != "for"
    )
    single_install = [item for item in single if item.command.executable == "install"]
    multi_install = [item for item in multi if item.command.executable == "install"]
    assert len(single_install) == 1
    assert len(multi_install) == 1
    assert single_install[0].constants["lang"] == "lit"
    assert single_install[0].constants == multi_install[0].constants

    required = collect_required_repository_paths(
        (
            _control_word_package(
                'lang=old\n  for f in a; do lang=lit; install "d/$lang" x; done'
            ),
        ),
        Path("/tmp/fixture-package"),
    )
    assert "d/old" not in required.paths
    assert required.paths == ("d/lit",)


def test_dynamic_assignment_after_control_word_fails_closed_like_multiline():
    """The taint the single-line form used to drop now withholds correlation."""

    single_body = (
        'lang=old\n  for f in a; do lang=$(cat v); install "d/$lang" x; done'
    )
    multi_body = (
        'lang=old\n  for f in a; do\n    lang=$(cat v)\n'
        '    install "d/$lang" x\n  done'
    )

    assert _control_word_scope(single_body) is None
    assert _control_word_scope(multi_body) is None

    single = collect_required_repository_paths(
        (_control_word_package(single_body),), Path("/tmp/fixture-package")
    )
    multi = collect_required_repository_paths(
        (_control_word_package(multi_body),), Path("/tmp/fixture-package")
    )
    assert single.complete is False
    assert single == multi
    assert "d/old" not in single.paths


def test_command_prefix_assignment_stays_untracked():
    """POSIX prefix assignments do not affect the current execution environment."""

    assert _constant_assignment_statement("x=1 install a b", {}) == (
        False,
        {},
        set(),
        set(),
    )
    assert _constant_assignment_statement("do x=1 install a b", {}) == (
        False,
        {},
        set(),
        set(),
    )

    scoped = _control_word_scope('x=1 install a b\n  install "$x" "$pkgdir/y"')

    assert scoped is not None
    installs = [item for item in scoped if item.command.executable == "install"]
    assert [item.constants.get("x") for item in installs] == [None, None]


def test_control_word_prefixed_nameref_stays_tainted():
    """Skipping the keyword must not turn a nameref into an ordinary scalar."""

    assert _nameref_declaration_names("do declare -n ref=x") == {"ref"}

    for body in (
        'for f in a; do declare -n ref=x; install "$ref/payload" "$pkgdir/y"; done',
        'for f in a; do\n    declare -n ref=x\n'
        '    install "$ref/payload" "$pkgdir/y"\n  done',
    ):
        assert _control_word_scope(body) is None
        required = collect_required_repository_paths(
            (_control_word_package(body),), Path("/tmp/fixture-package")
        )
        assert required.complete is False
        assert required.paths == ()


_EXPANSION_CHECKOUT = Path("/tmp/fixture-package")


def _expansion_package(value):
    return (
        "pkgname=fixture-package\n"
        "pkgver=3.2.0\n"
        "package() {\n"
        '  _source_dir="Shelly-ALPM-%s"\n'
        '  cd "$srcdir/${_source_dir}"\n'
        '  install "bin/tool" "$pkgdir/usr/bin/tool"\n'
        "}\n"
    ) % value


def _expansion_scope(value):
    return _scoped_commands(
        _expansion_package(value),
        _EXPANSION_CHECKOUT,
        top_level_repository_cwd=True,
        lifecycle_kind="pkgbuild",
    )


def _expansion_install(value):
    scoped = _expansion_scope(value)
    assert scoped is not None
    installs = [item for item in scoped if item.command.executable == "install"]
    assert len(installs) == 1
    return scoped, installs[0]


def test_bounded_expansion_resolves_known_constant():
    """A literal expansion over a known constant is provably side-effect-free.

    The A-shape pinned in ``findings/issue-001/residual-pin.py`` S3 used to
    leave ``_source_dir`` unresolved, tainting ``cd "$srcdir/${_source_dir}"``
    and withholding the whole scope.  A plain ``${pkgver}`` (A2) and the
    literal spelling (A3) keep their previous outcome.
    """

    assert (
        _resolve_bounded_expansion("${pkgver//+/-}", {"pkgver": "3.2.0"})
        == "3.2.0"
    )
    assert (
        _resolve_bounded_expansion("${pkgver//./-}", {"pkgver": "3.2.0"})
        == "3-2-0"
    )
    assert (
        _resolve_bounded_expansion("${pkgname%-git}", {"pkgname": "shelly-git"})
        == "shelly"
    )
    assert (
        _resolve_bounded_expansion("${pkgname#shelly-}", {"pkgname": "shelly-git"})
        == "git"
    )
    assert (
        _resolve_bounded_expansion("${pkgver:-fallback}", {"pkgver": "3.2.0"})
        == "3.2.0"
    )
    assert (
        _resolve_bounded_expansion("${empty:-fallback}", {"empty": ""})
        == "fallback"
    )
    assert _resolve_bounded_expansion("${empty+present}", {"empty": ""}) == "present"
    # The name is unknown, so ``:-`` must not resolve to its default word.
    assert (
        _resolve_bounded_expansion("${SHELLY_LIBALPM:-true}", {"pkgver": "3.2.0"})
        == "${SHELLY_LIBALPM:-true}"
    )

    outcomes = {}
    for label, value in (
        ("substitution", "${pkgver//+/-}"),
        ("expansion", "${pkgver}"),
        ("literal", "3.2.0"),
    ):
        scoped, install = _expansion_install(value)
        assert all(item.tainted_constants == () for item in scoped)
        assert install.constants["_source_dir"] == "Shelly-ALPM-3.2.0"
        assert install.repository_cwd == "src/Shelly-ALPM-3.2.0"
        outcomes[label] = (
            install.constants["_source_dir"],
            install.repository_cwd,
            install.tainted_constants,
        )
    assert outcomes["substitution"] == outcomes["expansion"] == outcomes["literal"]


@pytest.mark.parametrize(
    "form",
    (
        "${pkgver:=0}",
        "${pkgver=0}",
        "${pkgver:0}",
        "${pkgver:0:3}",
        "${pkgver[0]}",
        "${pkgname[pkgname=0]}",
        "${!pkgver}",
        "${!pkg*}",
        "${#pkgver}",
        "${pkgver?err}",
        "${pkgver:?err}",
        "${pkgver:+word}",
        "${pkgver//${pkgname}/x}",
        "${pkgver//$(id)/x}",
        "${pkgver//`id`/x}",
        "${pkgver//*/x}",
        "${pkgver/a?/x}",
        "${pkgver/[a]/x}",
        "${pkgver/#a/b}",
        "${pkgver/%a/b}",
        "${pkgver//a/}",
        "${pkgver/a}",
        "${}",
        "$${pkgver}",
    ),
)
def test_unsupported_expansion_forms_stay_unresolved(form):
    """Every form outside the allowlist returns the token unchanged."""

    constants = {"pkgname": "shelly-git", "pkgver": "3.2.0"}
    assert _resolve_bounded_expansion(form, constants) == form
    assert _static_assignment_value(form, form, constants) is None
    # The resolved prefix of a neighbouring form is not enough: a denied form
    # keeps the whole token unresolved.
    assert (
        _resolve_bounded_expansion("${pkgver}" + form, constants)
        == "${pkgver}" + form
    )
    # Oversized input is refused before any parsing.
    oversized = "${pkgver//" + "a" * 4096 + "/b}"
    assert _resolve_bounded_expansion(oversized, constants) == oversized


def test_expansion_side_effects_fail_closed(tmp_path):
    """The reference-grammar side effects must stay fail closed.

    ``:=``/``=`` assign, subscripts and substring offsets evaluate arithmetic,
    and an arithmetic read can recurse into a variable's value.  None of them
    may resolve to a constant or open a ``pkgname`` mutation path.
    """

    constants = {"pkgname": "fixture-package", "pkgver": "3.2.0"}
    for form in ("${pkgname:=0}", "${pkgname=0}", "${pkgname[pkgname=0]}"):
        assert _resolve_bounded_expansion(form, constants) == form
        assert _static_assignment_value(form, form, constants) is None

    assert _expansion_scope("${pkgver:=0}") is None
    assert _expansion_scope("${pkgver[pkgver=0]}") is None

    countercheck = {
        "parameter_default_write": 'pkgname=()\nx="${pkgname:=0}"',
        "arithmetic_recursive_read": 'a="pkgname=0"\ny=$((pkgname))',
        "parameter_index_write": 'x="${pkgname[pkgname=0]}"',
    }
    definitions = "package_a() {\n :\n}\npackage_b() {\n :\n}\n"
    for label, extra in countercheck.items():
        required = collect_required_repository_paths(
            ("pkgname=(a b)\n" + extra + "\n" + definitions,),
            tmp_path,
        )
        assert required.complete is False, label
        assert required.paths == (), label


def test_nested_expansion_is_not_laundered():
    """A denied nested pattern must never become an accepted literal form.

    ``_resolve`` still resolves plain references (today's behaviour) and runs
    repeatedly, so an unmasked ``${pkgname}`` inside a denied pattern would turn
    ``${pkgver//${pkgname}/x}`` into a literal substitution on a later pass.
    With ``pkgname=a/b`` that split would fabricate a different value than
    Bash's literal ``a/b`` pattern, i.e. a wrong path in the unsafe direction.
    """

    constants = {"pkgver": "a1a2", "pkgname": "a/b"}
    token = "${pkgver//${pkgname}/x}"
    for _index in range(4):
        assert _resolve(token, constants) == token
    assert _static_assignment_value(token, token, constants) is None
    assert _resolve_bounded_expansion(token, constants) == token


def test_denied_expansion_masks_only_itself():
    """Masking a denied construct must not stop unrelated references resolving."""

    assert _resolve("${x:=0}$cmd", {"cmd": "install"}) == "${x:=0}install"
    assert _resolve("${x:=0}$1", {"1": "arg"}) == "${x:=0}arg"
    assert (
        _resolve_bounded_expansion("${x:=0}$cmd", {"cmd": "install"})
        == "${x:=0}$cmd"
    )


# --- bounded compound/case/test syntax classification (R4/R5/R6) -----------

_SYNTAX_CHECKOUT = Path("/tmp/fixture-package")


def _syntax_package(body):
    return (
        "pkgname=('fixture')\n"
        "pkgver=3.2.0\n"
        'source=("fixture-${pkgver}.tar.gz::https://example.invalid/x.tar.gz")\n'
        "\n"
        "package_fixture() {\n" + body + "\n}\n"
    )


def _syntax_scope(body):
    return _scoped_commands(
        _syntax_package(body),
        _SYNTAX_CHECKOUT,
        top_level_repository_cwd=True,
        lifecycle_kind="pkgbuild",
    )


def _syntax_required(body):
    return collect_required_repository_paths(
        (_syntax_package(body),),
        _SYNTAX_CHECKOUT,
    )


_COMPOUND_TAINTED_SECOND = (
    "x=$(printf hello)\nb=lit\n"
    "if [[ $b == lit && $x == *'ell'* ]]; then return 1; fi"
)
_COMPOUND_TAINTED_FIRST = (
    "x=$(printf hello)\nb=lit\n"
    "if [[ $x == *'ell'* && $b == lit ]]; then return 1; fi"
)


def test_compound_conditional_is_operand_order_invariant():
    """``[[ A && B ]]`` is one expression, so operand order cannot matter.

    The shared segmenter splits the compound at ``&&``; the tail then parsed
    as a phantom command whose executable was the tainted ``$x`` operand, so
    one operand order withheld the scope and the reversed one did not.
    """

    for body in (_COMPOUND_TAINTED_SECOND, _COMPOUND_TAINTED_FIRST):
        scoped = _syntax_scope(body)
        assert scoped is not None
        compounds = [
            item.command for item in scoped if item.command.executable == "[["
        ]
        assert len(compounds) == 1
        assert "&&" in compounds[0].arguments
        assert compounds[0].arguments[-1] == "]]"
        assert all(item.command.executable != "$x" for item in scoped)
        # No pre-pass placeholder byte may survive into emitted evidence.
        for item in scoped:
            for value in (item.command.executable,) + item.command.arguments:
                assert all(ord(char) >= 32 for char in value)

    assert _syntax_required(_COMPOUND_TAINTED_SECOND) == _syntax_required(
        _COMPOUND_TAINTED_FIRST
    )


def test_conditional_fallback_fails_closed():
    """Every unbounded ``[[`` shape keeps today's split-and-fail outcome."""

    unbalanced = (
        "x=$(printf hello)\nb=lit\n"
        "if [[ $b == lit && $x == *ell*; then return 1; fi"
    )
    oversized = (
        "x=$(printf hello)\nb=lit\n"
        "if [[ $b == " + "a" * 4100 + " && $x == *ell* ]]; then return 1; fi"
    )
    too_many = "true\n" + "[[ $a == b ]];\n" * 9
    quoted_argument = 'printf "%s" "[[ a && b ]]"\n'

    for text in (unbalanced, oversized, too_many, quoted_argument):
        assert _mask_conditional_compound_operators(text) == (text, {})

    # A pre-pass refusal is not an allow: the tainted tail still withholds
    # the same scope it did before the pre-pass existed.
    assert _syntax_scope(unbalanced) is None
    assert _syntax_scope(oversized) is None


def test_operator_outside_compound_still_splits():
    """Only operators inside a bounded span are masked, never shell ones."""

    body = (
        "if [[ $a == b ]]; then :; fi\n"
        '[[ $c == d ]] && install -Dm755 "$srcdir/e" d'
    )
    scoped = _syntax_scope(body)
    assert scoped is not None
    compounds = [
        item.command for item in scoped if item.command.executable == "[["
    ]
    assert len(compounds) == 2
    assert any(item.command.executable == "install" for item in scoped)
    assert "src/e" in _syntax_required(body).paths


def _top_level_case_package(top_level):
    return _syntax_package("").replace(
        "package_fixture() {",
        top_level + "\npackage_fixture() {",
        1,
    )


def test_case_arm_patterns_are_not_commands():
    """Arm patterns are string-match data, never commands or operands.

    The shared segmenter treats each ``)`` as a boundary, so ``a)`` and ``*)``
    used to emit phantom ``a``/``*`` commands; the ``*`` operand then flipped
    repository completeness through the glob-ambiguity rule.
    """

    with_star = _top_level_case_package(
        "case $x in\n  a) y=1 ;;\n  *) return 1 ;;\nesac"
    )
    without_star = _top_level_case_package(
        "case $x in\n  a) y=1 ;;\nesac"
    )

    for text in (with_star, without_star):
        scoped = _scoped_commands(
            text,
            _SYNTAX_CHECKOUT,
            top_level_repository_cwd=True,
            lifecycle_kind="pkgbuild",
        )
        assert scoped is not None
        executables = [item.command.executable for item in scoped]
        assert "a" not in executables
        assert "*" not in executables

    assert collect_required_repository_paths(
        (with_star,), _SYNTAX_CHECKOUT
    ) == collect_required_repository_paths((without_star,), _SYNTAX_CHECKOUT)
    assert (
        collect_required_repository_paths(
            (with_star,), _SYNTAX_CHECKOUT
        ).complete
        is True
    )

    # A command substitution in a pattern still runs in Bash, so only literal
    # pattern text is blanked and the substituted command stays visible.
    substitution = _syntax_scope(
        "case $x in\n  $(printf p)) y=1 ;;\nesac"
    )
    assert substitution is not None
    assert any(
        item.command.executable == "printf" for item in substitution
    )


def test_case_arm_body_commands_still_captured():
    """Suppressing patterns must not suppress the commands inside the arms."""

    body = (
        "case $x in\n"
        '  a) install -Dm755 "$srcdir/b" d ;;\n'
        "  *) return 1 ;;\n"
        "esac"
    )
    scoped = _syntax_scope(body)
    assert scoped is not None
    assert any(
        item.command.executable == "install" for item in scoped
    )
    assert "src/b" in _syntax_required(body).paths


def test_case_suppression_fallback_fails_closed():
    """Unbounded case text keeps today's phantom-command outcome."""

    unterminated = "case $x in\n  a) y=1 ;;\n  *) y=2 ;;"
    assert _blank_case_arm_patterns(unterminated) == unterminated
    missing_in = "case $x esac"
    assert _blank_case_arm_patterns(missing_in) == missing_in

    nested = "esac"
    for _depth in range(5):
        nested = "case $x in\n  a) " + nested + " ;;\nesac"
    assert _blank_case_arm_patterns(nested) == nested

    # A refusal is not an allow: the phantom ``*`` operand still flips
    # repository completeness exactly as it did before suppression existed.
    text = _top_level_case_package(unterminated + "\n")
    assert collect_required_repository_paths(
        (text,), _SYNTAX_CHECKOUT
    ).complete is False


def test_shelly_recipe_remains_required_incomplete():
    """The recorded recipe stays blocked by the retained dynamic-lang limit.

    R4/R5/R6 classify bounded compound, case-arm and test syntax only.  The
    recipe still fails closed because a dynamically produced ``lang`` value
    feeds an install path (the retained R2 limit), not because of a family
    fixed here: replacing only those assignments with a literal lets the
    recorded recipe parse.
    """

    content = SHELLY_PKGBUILD.read_text(encoding="utf-8")
    result = analyze(content, artifact())
    incomplete = finding(result, "AUR-REPO-INSPECTION-INCOMPLETE-001")
    assert incomplete.blocks_installation is True
    assert result.is_safe is False

    required = collect_required_repository_paths(
        (content,),
        _SYNTAX_CHECKOUT,
    )
    assert required.complete is False
    assert required.paths == ()

    control = re.sub(
        r"(?m)^(\s*)lang=\$\([^\n]*\)$",
        r"\1lang=lit",
        content,
    )
    assert control != content
    assert control.count("lang=lit") == 4
    assert (
        _scoped_commands(
            control,
            _SYNTAX_CHECKOUT,
            top_level_repository_cwd=True,
            lifecycle_kind="pkgbuild",
        )
        is not None
    )
