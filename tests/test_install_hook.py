import hashlib
import os
from pathlib import Path

import pytest

import aurascan.core.install_hook as install_hook_module
from aurascan.core.install_hook import (
    INSTALL_HOOK_NONE,
    INSTALL_HOOK_RESOLVED,
    INSTALL_HOOK_UNINSPECTED,
    PackageScanInputError,
    build_scan_input_digest,
    capture_package_scan_input,
    resolve_install_hook,
)


def write_pkgbuild(root: Path, declaration: str = ""):
    content = "pkgname=demo\npkgver=1\n"
    if declaration:
        content += declaration + "\n"
    path = root / "PKGBUILD"
    path.write_text(content, encoding="utf-8")
    return path, content


def test_resolves_literal_dot_prefixed_hook_without_execution(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=.demo.install")
    hook = tmp_path / ".demo.install"
    raw_hook = b"post_install() { printf '%s\\n' 'inert fixture'; }\n"
    hook.write_bytes(raw_hook)

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.declared is True
    assert result.legacy is False
    assert result.path == hook
    assert result.content_sha256 == hashlib.sha256(raw_hook).hexdigest()
    assert result.input_digest
    assert result.declaration_line == 3


def test_resolves_quoted_literal_hook_with_trailing_comment(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(
        tmp_path,
        "install='demo hook.install'  # local package hook",
    )
    hook = tmp_path / "demo hook.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == hook


@pytest.mark.parametrize(
    "declaration",
    [
        "readonly install=demo.install",
        "export install=demo.install",
        "pkgname=demo; install=demo.install",
        "pkgname=demo; readonly install=demo.install",
    ],
)
def test_resolves_supported_shell_assignment_forms(tmp_path: Path, declaration: str):
    pkgbuild, content = write_pkgbuild(tmp_path, declaration)
    hook = tmp_path / "demo.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == hook


def test_hash_inside_assignment_word_is_not_treated_as_a_comment(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=real.install#suffix")
    intended = tmp_path / "real.install#suffix"
    intended.write_text("post_install() { :; }\n", encoding="utf-8")
    (tmp_path / "real.install").write_text("decoy\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == intended


@pytest.mark.parametrize("redirection", [";", ">sink", ">>build.log"])
def test_shell_terminators_and_attached_redirections_cannot_select_a_decoy(
    tmp_path: Path,
    redirection: str,
):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=real.install" + redirection)
    intended = tmp_path / "real.install"
    intended.write_text("post_install() { :; }\n", encoding="utf-8")
    (tmp_path / ("real.install" + redirection)).write_text("decoy\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == intended


def test_single_quoted_backslash_before_terminator_cannot_select_a_decoy(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install='real\\';")
    intended = tmp_path / "real\\"
    intended.write_text("post_install() { :; }\n", encoding="utf-8")
    (tmp_path / "real\\;").write_text("decoy\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == intended


@pytest.mark.parametrize(
    "declaration",
    [
        "pkgname=demo 2>build.log install=real.install",
        "2>/dev/null install=real.install",
        "pkgname=demo >|build.log install=real.install",
        ">|build.log install=real.install",
        "pkgname=demo &>build.log install=real.install",
    ],
)
def test_interspersed_redirections_do_not_hide_later_assignments(
    tmp_path: Path,
    declaration: str,
):
    pkgbuild, content = write_pkgbuild(tmp_path, declaration)
    hook = tmp_path / "real.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == hook


def test_multiline_quotes_arrays_and_heredocs_do_not_declare_hooks(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += (
        "message='documentation starts\n"
        "install=quoted.install\n"
        "documentation ends'\n"
        "examples=(\n"
        "  install=array.install\n"
        ")\n"
        "cat <<'END-DOC'\n"
        "install=heredoc.install\n"
        "END-DOC\n"
    )

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_NONE
    assert result.declared is False


def test_hash_inside_array_word_does_not_hide_a_later_hook_declaration(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += "dummy=(foo#bar)\ninstall=real.install\n"
    hook = tmp_path / "real.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == hook


@pytest.mark.parametrize(
    "assignment",
    [
        "inst\\\nall=real.install",
        "export inst\\\nall=real.install",
        "install\\\n=real.install",
    ],
)
def test_backslash_continuation_cannot_split_the_install_name(
    tmp_path: Path,
    assignment: str,
):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += assignment + "\n"
    hook = tmp_path / "real.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == hook


def test_single_quoted_backslash_newline_text_is_not_an_assignment(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += "message='inst\\\nall=other.install'\n"

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_NONE
    assert result.declared is False


@pytest.mark.parametrize(
    "arithmetic",
    [
        ": $((1 << true))",
        "echo '))'; : $((1 << true))",
        ": $[1 << true]",
        ": $[arr[0] << true]",
    ],
)
def test_arithmetic_shift_is_not_misread_as_a_heredoc(tmp_path: Path, arithmetic: str):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += arithmetic + "\ninstall=real.install\ntrue\n"
    hook = tmp_path / "real.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.path == hook


@pytest.mark.parametrize(
    "expansion",
    [
        "${install:=other.install}",
        "${install=other.install}",
        "$((install=123))",
    ],
)
def test_unquoted_heredoc_install_mutation_fails_closed(tmp_path: Path, expansion: str):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += ": <<EOF\n" + expansion + "\nEOF\n"

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_UNINSPECTED
    assert result.declared is True
    assert result.error_code == "dynamic_declaration"


def test_quoted_heredoc_install_expansion_is_inert(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += ": <<'EOF'\n${install:=other.install}\n$((install=123))\nEOF\n"

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_NONE
    assert result.declared is False


@pytest.mark.parametrize(
    "declaration",
    [
        "install+=other.install",
        "printf -v install %s other.install",
        "read -r install <<< other.install",
        "install[0]=other.install",
    ],
)
def test_noncanonical_install_mutation_fails_closed(tmp_path: Path, declaration: str):
    pkgbuild, content = write_pkgbuild(tmp_path, declaration)

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_UNINSPECTED
    assert result.declared is True


def test_exact_input_digest_changes_for_pkgbuild_bytes_and_hook_bytes(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=demo.install")
    hook = tmp_path / "demo.install"
    hook.write_bytes(b"post_install() { :; }\n")
    first = resolve_install_hook(pkgbuild, content)
    first_scan = build_scan_input_digest(pkgbuild.read_bytes(), first)

    crlf_bytes = pkgbuild.read_bytes().replace(b"\n", b"\r\n")
    assert build_scan_input_digest(crlf_bytes, first) != first_scan

    hook.write_bytes(b"post_install() { printf 'changed'; }\n")
    second = resolve_install_hook(pkgbuild, content)
    assert second.input_digest != first.input_digest
    assert build_scan_input_digest(pkgbuild.read_bytes(), second) != first_scan


def test_shared_capture_returns_the_exact_pkgbuild_and_hook_identity(tmp_path: Path):
    pkgbuild, _content = write_pkgbuild(tmp_path, "install=demo.install")
    hook = tmp_path / "demo.install"
    hook.write_bytes(b"post_install() { :; }\n")

    captured = capture_package_scan_input(pkgbuild)

    assert captured.pkgbuild_bytes == pkgbuild.read_bytes()
    assert captured.install_hook.status == INSTALL_HOOK_RESOLVED
    assert captured.input_digest == build_scan_input_digest(
        captured.pkgbuild_bytes,
        captured.install_hook,
    )


def test_shared_capture_rejects_pkgbuild_replacement_during_read(tmp_path: Path, monkeypatch):
    pkgbuild, _content = write_pkgbuild(tmp_path)
    replacement = tmp_path / "replacement"
    replacement.write_text("pkgname=replaced\npkgver=2\n", encoding="utf-8")
    original_read = install_hook_module.os.read
    replaced = {"done": False}

    def replacing_read(file_descriptor, size):
        chunk = original_read(file_descriptor, size)
        if not replaced["done"]:
            replaced["done"] = True
            os.replace(str(replacement), str(pkgbuild))
        return chunk

    monkeypatch.setattr(install_hook_module.os, "read", replacing_read)

    with pytest.raises(PackageScanInputError) as error:
        capture_package_scan_input(pkgbuild)

    assert error.value.code == "replaced_during_read"


def test_hook_digest_detects_same_size_change_with_restored_mtime(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=demo.install")
    hook = tmp_path / "demo.install"
    hook.write_bytes(b"AAAA")
    before = hook.stat()
    first = resolve_install_hook(pkgbuild, content)

    hook.write_bytes(b"BBBB")
    os.utime(str(hook), ns=(before.st_atime_ns, before.st_mtime_ns))
    second = resolve_install_hook(pkgbuild, content)

    assert first.content_sha256 != second.content_sha256
    assert first.input_digest != second.input_digest


@pytest.mark.parametrize(
    ("declaration", "error_code"),
    [
        ("install=$pkgname.install", "dynamic_declaration"),
        ("install=../outside.install", "unsafe_path"),
        ("install=/tmp/outside.install", "unsafe_path"),
        ("install=", "empty_declaration"),
        ("install='unterminated", "invalid_declaration"),
        ("install=first.install second.install", "ambiguous_declaration"),
    ],
)
def test_rejects_non_literal_or_unsafe_declarations(tmp_path: Path, declaration: str, error_code: str):
    pkgbuild, content = write_pkgbuild(tmp_path, declaration)

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_UNINSPECTED
    assert result.declared is True
    assert result.error_code == error_code
    assert result.input_digest


def test_missing_and_ambiguous_declarations_have_distinct_failure_identities(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=missing.install")
    missing = resolve_install_hook(pkgbuild, content)
    ambiguous_content = content + "install=other.install\n"
    ambiguous = resolve_install_hook(pkgbuild, ambiguous_content)

    assert missing.status == INSTALL_HOOK_UNINSPECTED
    assert missing.error_code == "missing_or_unreadable"
    assert ambiguous.error_code == "ambiguous_declaration"
    assert missing.input_digest != ambiguous.input_digest


def test_commented_install_assignment_is_not_a_declaration(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path)
    content += "# install=missing.install\n"

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_NONE
    assert result.declared is False


def test_rejects_final_symlink_and_symlink_directory(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=hook.install")
    outside = tmp_path / "outside.install"
    outside.write_text("post_install() { :; }\n", encoding="utf-8")
    (tmp_path / "hook.install").symlink_to(outside)

    final_link = resolve_install_hook(pkgbuild, content)

    assert final_link.status == INSTALL_HOOK_UNINSPECTED
    assert final_link.error_code == "symlink"

    (tmp_path / "hook.install").unlink()
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    (real_directory / "hook.install").write_text("post_install() { :; }\n", encoding="utf-8")
    (tmp_path / "linked").symlink_to(real_directory, target_is_directory=True)
    directory_link = resolve_install_hook(pkgbuild, content.replace("hook.install", "linked/hook.install"))

    assert directory_link.status == INSTALL_HOOK_UNINSPECTED
    assert directory_link.error_code == "unsafe_parent"


def test_rejects_fifo_and_oversized_hook_without_blocking_on_fifo(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=hook.install")
    hook = tmp_path / "hook.install"
    os.mkfifo(str(hook))

    fifo = resolve_install_hook(pkgbuild, content, max_bytes=4)

    assert fifo.status == INSTALL_HOOK_UNINSPECTED
    assert fifo.error_code == "not_regular"

    hook.unlink()
    hook.write_bytes(b"12345")
    oversized = resolve_install_hook(pkgbuild, content, max_bytes=4)
    assert oversized.status == INSTALL_HOOK_UNINSPECTED
    assert oversized.error_code == "oversized"


def test_rejects_directory_hook(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=hook.install")
    (tmp_path / "hook.install").mkdir()

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_UNINSPECTED
    assert result.error_code == "not_regular"


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read mode-000 fixtures")
def test_unreadable_hook_is_uninspected(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=hook.install")
    hook = tmp_path / "hook.install"
    hook.write_bytes(b"post_install() { :; }\n")
    hook.chmod(0)
    try:
        result = resolve_install_hook(pkgbuild, content)
    finally:
        hook.chmod(0o600)

    assert result.status == INSTALL_HOOK_UNINSPECTED
    assert result.error_code == "missing_or_unreadable"


def test_detects_atomic_replacement_during_read(tmp_path: Path, monkeypatch):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=hook.install")
    hook = tmp_path / "hook.install"
    hook.write_bytes(b"post_install() { :; }\n")
    replacement = tmp_path / "replacement.install"
    replacement.write_bytes(b"post_install() { printf 'replacement'; }\n")
    original_read = install_hook_module.os.read
    replaced = {"done": False}

    def replacing_read(file_descriptor, size):
        chunk = original_read(file_descriptor, size)
        if not replaced["done"]:
            replaced["done"] = True
            os.replace(str(replacement), str(hook))
        return chunk

    monkeypatch.setattr(install_hook_module.os, "read", replacing_read)

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_UNINSPECTED
    assert result.error_code == "replaced_during_read"


def test_legacy_install_hash_remains_raw_content_hash(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path)
    raw_hook = b"post_install() { :; }\n"
    (tmp_path / ".INSTALL").write_bytes(raw_hook)

    normal = resolve_install_hook(pkgbuild, content)
    legacy = resolve_install_hook(pkgbuild, content, allow_legacy_install=True)

    assert normal.status == INSTALL_HOOK_NONE
    assert normal.input_digest == ""
    assert legacy.status == INSTALL_HOOK_RESOLVED
    assert legacy.declared is False
    assert legacy.legacy is True
    assert legacy.content_sha256 == hashlib.sha256(raw_hook).hexdigest()


def test_hashes_raw_invalid_utf8_while_analysis_text_is_replaced(tmp_path: Path):
    pkgbuild, content = write_pkgbuild(tmp_path, "install=hook.install")
    raw_hook = b"post_install() { printf '\xff'; }\n"
    (tmp_path / "hook.install").write_bytes(raw_hook)

    result = resolve_install_hook(pkgbuild, content)

    assert result.status == INSTALL_HOOK_RESOLVED
    assert result.content_sha256 == hashlib.sha256(raw_hook).hexdigest()
    assert "\ufffd" in result.content
