import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from aurascan.core.models import Severity
from aurascan.core.source_acquisition import (
    ChecksumVerifier,
    GitSourceFetcher,
    HttpSourceFetcher,
    PgpKeyNormalizer,
    PublicKeySource,
    SignatureVerifier,
    SourceAcquisitionResult,
    SourceFetcher,
    SourceKind,
    SourceParser,
    SourcePolicy,
    SourceReference,
    TrustedKeyDirectoryProvider,
)
from aurascan.core.trusted_tools import run_bounded_trusted_tool


def parse_pkgbuild(content: str):
    return SourceParser().parse_pkgbuild(content, "PKGBUILD")


def test_native_tool_runner_captures_small_output_with_fixed_shape():
    result = run_bounded_trusted_tool(
        ["/usr/bin/printf", "bounded-output"],
        capture_output=True,
        text=True,
        timeout=2,
        check=True,
    )

    assert result.returncode == 0
    assert result.stdout == "bounded-output"
    assert result.stderr == ""


def test_native_tool_runner_terminates_oversized_output():
    with pytest.raises(subprocess.SubprocessError, match="safety bound"):
        run_bounded_trusted_tool(
            ["/usr/bin/yes", "bounded-output"],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )


def test_parse_local_source():
    refs, findings = parse_pkgbuild("pkgname=demo\nsource=(local.tar.gz)\nsha256sums=(SKIP)\n")

    assert findings == []
    assert refs[0].kind == SourceKind.local
    assert refs[0].resolved == "local.tar.gz"
    assert refs[0].filename == "local.tar.gz"


def test_parse_https_source():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nsha256sums=(abc)\n')

    assert refs[0].kind == SourceKind.http
    assert refs[0].filename == "demo.tar.gz"


def test_parse_renamed_source_syntax():
    refs, _ = parse_pkgbuild('source=("renamed.tar.gz::https://example.invalid/source.tar.gz")\nsha256sums=(abc)\n')

    assert refs[0].kind == SourceKind.http
    assert refs[0].filename == "renamed.tar.gz"
    assert refs[0].resolved == "https://example.invalid/source.tar.gz"


def test_parse_basic_variable_interpolation():
    refs, _ = parse_pkgbuild('pkgname=demo\npkgver=1.2.3\nsource=("https://example.invalid/$pkgname-${pkgver}.tar.gz")\nsha256sums=(abc)\n')

    assert refs[0].resolved == "https://example.invalid/demo-1.2.3.tar.gz"
    assert refs[0].unexpanded_original == (
        "https://example.invalid/$pkgname-${pkgver}.tar.gz"
    )
    assert refs[0].checkout_name_proven_static is True


def test_parse_unquoted_common_variables_as_proven_static_source_name():
    refs, findings = parse_pkgbuild(
        "pkgname=demo\n"
        "pkgbase=demo-suite\n"
        "pkgver=1.2.3\n"
        "pkgrel=4\n"
        "source=($pkgbase-$pkgname-${pkgver}-${pkgrel}.tar.gz)\n"
        "sha256sums=(abc)\n"
    )

    assert findings == []
    assert refs[0].resolved == "demo-suite-demo-1.2.3-4.tar.gz"
    assert refs[0].checkout_name_proven_static is True


@pytest.mark.parametrize(
    ("source_word", "expected"),
    (
        ("'$pkgname-${pkgver}.tar.gz'", "$pkgname-${pkgver}.tar.gz"),
        (r"\$pkgname-${pkgver}.tar.gz", "$pkgname-1.2.3.tar.gz"),
        (r'"\$pkgname-${pkgver}.tar.gz"', "$pkgname-1.2.3.tar.gz"),
    ),
)
def test_literal_or_escaped_dollar_is_not_proven_checkout_name(
    source_word,
    expected,
):
    refs, findings = parse_pkgbuild(
        "pkgname=demo\n"
        "pkgver=1.2.3\n"
        f"source=({source_word})\n"
        "sha256sums=(abc)\n"
    )

    assert findings == []
    assert refs[0].resolved == expected
    assert refs[0].checkout_name_proven_static is False


@pytest.mark.parametrize(
    ("source_word", "expected"),
    (
        ('"$pkgname-$flavor.tar.gz"', "demo-$flavor.tar.gz"),
        ('"$pkgname-${flavor}.tar.gz"', "demo-${flavor}.tar.gz"),
        ('"$pkgname_suffix.tar.gz"', "$pkgname_suffix.tar.gz"),
    ),
)
def test_unknown_source_variable_is_retained_but_not_proven(
    source_word,
    expected,
):
    refs, findings = parse_pkgbuild(
        "pkgname=demo\n"
        f"source=({source_word})\n"
        "sha256sums=(abc)\n"
    )

    assert findings == []
    assert refs[0].resolved == expected
    assert refs[0].checkout_name_proven_static is False


def test_dynamic_basic_variable_does_not_prove_source_interpolation():
    refs, findings = parse_pkgbuild(
        'pkgname="$(printf demo)"\n'
        'source=("$pkgname.tar.gz")\n'
        "sha256sums=(abc)\n"
    )

    assert findings == []
    assert refs[0].resolved == "$pkgname.tar.gz"
    assert refs[0].checkout_name_proven_static is False


@pytest.mark.parametrize("operator", ("@", "+", "!", "?", "*"))
def test_unquoted_extglob_source_word_is_not_proven_checkout_name(operator):
    source_word = f"prefix-{operator}(payload|alternate).bin"
    refs, findings = parse_pkgbuild(
        f"source=({source_word})\n"
        "sha256sums=(abc)\n"
    )

    assert findings == []
    assert refs[0].resolved == source_word
    assert refs[0].checkout_name_proven_static is False


@pytest.mark.parametrize("operator", ("@", "+", "!", "?", "*"))
def test_quoted_extglob_spelling_remains_a_proven_literal(operator):
    source_word = f"prefix-{operator}(payload|alternate).bin"
    refs, findings = parse_pkgbuild(
        f'source=("{source_word}")\n'
        "sha256sums=(abc)\n"
    )

    assert findings == []
    assert refs[0].resolved == source_word
    assert refs[0].checkout_name_proven_static is True


def test_fully_escaped_extglob_spelling_remains_a_proven_literal():
    refs, findings = parse_pkgbuild(
        r"source=(prefix-\@\(payload\|alternate\).bin)" + "\n"
        "sha256sums=(abc)\n"
    )

    assert findings == []
    assert refs[0].resolved == "prefix-@(payload|alternate).bin"
    assert refs[0].checkout_name_proven_static is True


@pytest.mark.parametrize(
    "content",
    (
        'pkgver=payload\npkgver=benign\nsource=("$pkgver")\n',
        'pkgver=(payload)\nsource=("$pkgver")\n',
        'source=("$pkgver")\npkgver=payload\n',
        'pkgver=payload\ndeclare pkgver=benign\nsource=("$pkgver")\n',
        'pkgver=payload\nprintf -v pkgver "%s" benign\nsource=("$pkgver")\n',
        'pkgver=payload\nbuiltin printf -v pkgver "%s" benign\nsource=("$pkgver")\n',
        'pkgver=payload\ncommand printf -v pkgver "%s" benign\nsource=("$pkgver")\n',
        'pkgver=payload\nwait -p pkgver 123\nsource=("$pkgver")\n',
        'pkgver=payload\ncoproc pkgver { true; }\nsource=("$pkgver")\n',
        'pkgver=payload\nexec {pkgver}<>/dev/null\nsource=("$pkgver")\n',
        'pkgver=payload\n((pkgver=1))\nsource=("$pkgver")\n',
        'pkgver=payload\nfor pkgver in benign; do :; done\nsource=("$pkgver")\n',
    ),
)
def test_ambiguous_basic_variable_mutation_never_proves_checkout_name(content):
    refs, findings = parse_pkgbuild(content)

    assert findings == []
    assert refs[0].checkout_name_proven_static is False


def test_indirect_nameref_mutation_withholds_source_mapping_entirely():
    refs, findings = parse_pkgbuild(
        'pkgver=payload\ndeclare -n alias=pkgver\nsource=("$pkgver")\n'
    )

    assert refs == []
    assert any(
        finding.rule_id == "SOURCE-PARSER-AMBIGUOUS"
        for finding in findings
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "trap 'source=(payload)' DEBUG",
        "builtin printf -v source '%s' payload",
        "command printf -v source '%s' payload",
        "wait -p source 123",
        "coproc source { true; }",
        "exec {source}<>/dev/null",
        "for source in payload; do :; done",
        "select source in payload; do break; done",
        "getopts a source",
        "let 'source=1'",
        "((source=1))",
        "shopt -s expand_aliases\nalias mutate='source=(payload)'\nmutate",
    ),
)
def test_top_level_shell_mutation_primitives_make_source_collection_ambiguous(
    mutation,
):
    refs, findings = parse_pkgbuild(
        mutation + '\nsource=("benign")\nsha256sums=("fixture")\n'
    )

    assert refs == []
    assert any(
        finding.rule_id == "SOURCE-PARSER-AMBIGUOUS"
        and finding.blocks_installation
        for finding in findings
    )


def test_called_helper_that_mutates_basic_variable_withholds_source_mapping():
    refs, findings = parse_pkgbuild(
        "pkgver=1\n"
        "mutate() { pkgver=2; }\n"
        "mutate\n"
        'source=("foo-$pkgver")\n'
    )

    assert refs == []
    assert any(
        finding.rule_id == "SOURCE-PARSER-AMBIGUOUS"
        for finding in findings
    )


def test_basic_variable_proof_ignores_function_and_heredoc_body_assignments():
    refs, findings = parse_pkgbuild(
        "pkgver=1.2.3\n"
        "helper() { pkgver=other; }\n"
        "readme=$(cat <<'EOF'\n"
        "pkgver=also-other\n"
        "EOF\n"
        ")\n"
        'source=("demo-$pkgver.tar.gz")\n'
    )

    assert findings == []
    assert refs[0].resolved == "demo-1.2.3.tar.gz"
    assert refs[0].checkout_name_proven_static is True


@pytest.mark.parametrize("quoted", (False, True))
def test_git_source_fragment_is_retained_inside_source_word(quoted):
    source = (
        "git+https://example.invalid/repo.git#"
        "commit=0123456789abcdef0123456789abcdef01234567"
    )
    source_word = '"' + source + '"' if quoted else source

    refs, findings = parse_pkgbuild(
        f"source=({source_word})\nsha256sums=(SKIP)\n"
    )

    assert findings == []
    assert refs[0].resolved == source
    assert refs[0].fragment_type == "commit"


def test_source_array_word_start_hash_remains_a_comment():
    refs, findings = parse_pkgbuild(
        "source=(one.tar # ignored fragment-looking text\n two.tar)\n"
        "sha256sums=(one two)\n"
    )

    assert findings == []
    assert [reference.resolved for reference in refs] == ["one.tar", "two.tar"]


@pytest.mark.parametrize("source_word", ("payload-*.tar", "payload-{one,two}"))
def test_unquoted_shell_expansion_never_proves_checkout_name(source_word):
    refs, findings = parse_pkgbuild(f"source=({source_word})\n")

    assert findings == []
    assert refs[0].checkout_name_proven_static is False


def test_quoted_literal_braces_can_still_prove_checkout_name():
    refs, findings = parse_pkgbuild('source=("payload-{one,two}")\n')

    assert findings == []
    assert refs[0].resolved == "payload-{one,two}"
    assert refs[0].checkout_name_proven_static is True


def test_parse_srcinfo_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/demo.tar.gz
	sha256sums = abc
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert refs[0].kind == SourceKind.http
    assert refs[0].checksum == "abc"
    assert refs[0].checkout_name_proven_static is True


def test_parse_srcinfo_sha512_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/demo.tar.gz
	sha512sums = abc
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "sha512"


def test_parse_pkgbuild_b2_source_metadata():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nb2sums=(abc)\n')

    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "b2"


def test_parse_srcinfo_md5_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/demo.tar.gz
	md5sums = abc
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "md5"


def test_parse_pkgbuild_sha1_source_metadata():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nsha1sums=(abc)\n')

    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "sha1"


def test_parse_srcinfo_arch_specific_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/common.tar.gz
	source_x86_64 = https://example.invalid/x86_64.tar.gz
	sha256sums = common
	sha256sums_x86_64 = x86_64
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert [ref.resolved for ref in refs] == [
        "https://example.invalid/common.tar.gz",
        "https://example.invalid/x86_64.tar.gz",
    ]
    assert [ref.checksum for ref in refs] == ["common", "x86_64"]
    assert all(ref.checksum_algorithm == "sha256" for ref in refs)


def test_parse_uses_captured_pkgbuild_instead_of_neighbor_srcinfo(tmp_path: Path):
    pkgbuild = tmp_path / "PKGBUILD"
    content = 'source=("package-source.tar")\nsha256sums=(package-digest)\n'
    pkgbuild.write_text(content, encoding="utf-8")
    (tmp_path / ".SRCINFO").write_text(
        "pkgbase = demo\n\tsource = cover-source.tar\n\tsha256sums = cover-digest\n",
        encoding="utf-8",
    )

    refs, findings = SourceParser().parse(str(pkgbuild), content)

    assert findings == []
    assert [ref.resolved for ref in refs] == ["package-source.tar"]
    assert [ref.checksum for ref in refs] == ["package-digest"]


def test_parse_pkgbuild_arch_specific_source_metadata():
    refs, findings = parse_pkgbuild(
        'source=("common.tar.gz")\n'
        'source_x86_64=("https://example.invalid/x86_64.tar.gz")\n'
        'sha256sums=(common)\n'
        'sha256sums_x86_64=(x86_64)\n'
    )

    assert findings == []
    assert [ref.resolved for ref in refs] == [
        "common.tar.gz",
        "https://example.invalid/x86_64.tar.gz",
    ]
    assert [ref.checksum for ref in refs] == ["common", "x86_64"]


def test_parse_indented_source_assignment_instead_of_returning_false_clear():
    refs, findings = parse_pkgbuild(
        '  source=("https://example.invalid/indented.tar.gz")\n'
        'sha256sums=(abc)\n'
    )

    assert findings == []
    assert [ref.resolved for ref in refs] == ["https://example.invalid/indented.tar.gz"]


def test_parse_source_append_assignments_in_order():
    refs, findings = parse_pkgbuild(
        'source=("local.tar")\n'
        'source+=("https://example.invalid/appended.tar")\n'
        'sha256sums=(one two)\n'
    )

    assert findings == []
    assert [ref.resolved for ref in refs] == [
        "local.tar",
        "https://example.invalid/appended.tar",
    ]


def test_parse_array_parenthesis_inside_quoted_filename():
    refs, findings = parse_pkgbuild(
        'source=("local)name.tar" "https://example.invalid/remote.tar")\n'
        'sha256sums=(one two)\n'
    )

    assert findings == []
    assert [ref.resolved for ref in refs] == [
        "local)name.tar",
        "https://example.invalid/remote.tar",
    ]


def test_quoted_source_assignment_documentation_is_not_a_declaration():
    refs, findings = parse_pkgbuild(
        "printf '%s\\n' 'source=(https://example.invalid/documentation.tar)'\n"
    )

    assert refs == []
    assert findings == []


@pytest.mark.parametrize(
    "content",
    [
        "source helper-that-mutates-pkgbuild.sh\n",
        "eval 'source=(https://example.invalid/dynamic.tar)'\n",
        "source[0]=https://example.invalid/replaced.tar\n",
        'source=("benign.tar")\ndeclare -n ref=source\nref+=("https://example.invalid/dynamic.tar")\n',
        'source=("benign.tar")\ntypeset -n alias=source\nalias[0]="https://example.invalid/dynamic.tar"\n',
        "source = (https://example.invalid/malformed.tar)\n",
        'source=("unterminated.tar\n',
    ],
)
def test_unrepresentable_source_mutation_fails_closed(content: str):
    refs, findings = parse_pkgbuild(content)

    assert refs == []
    assert any(
        finding.rule_id == "SOURCE-PARSER-AMBIGUOUS"
        and finding.blocks_installation
        for finding in findings
    )


def test_dynamic_commands_inside_package_function_do_not_hide_static_sources():
    refs, findings = parse_pkgbuild(
        'source=("https://example.invalid/static.tar")\n'
        'sha256sums=(abc)\n'
        'package() {\n'
        '  eval "$generated_command"\n'
        '  source helper-used-during-package.sh\n'
        '}\n'
    )

    assert findings == []
    assert [ref.resolved for ref in refs] == ["https://example.invalid/static.tar"]


@pytest.mark.parametrize("package_name", ("foo-bar", "foo+bar", "foo.bar", "foo@bar"))
def test_dynamic_commands_inside_split_package_function_are_inert_metadata(
    package_name: str,
):
    refs, findings = parse_pkgbuild(
        f"pkgname=({package_name})\n"
        'source=("https://example.invalid/static.tar")\n'
        "sha256sums=(abc)\n"
        f"package_{package_name}() {{\n"
        '  eval "$generated_command"\n'
        '  source helper-used-during-package.sh\n'
        "}\n"
    )

    assert findings == []
    assert [ref.resolved for ref in refs] == [
        "https://example.invalid/static.tar"
    ]


def test_unterminated_package_function_keeps_source_parser_fail_closed():
    refs, findings = parse_pkgbuild(
        'source=("https://example.invalid/static.tar")\n'
        'package() {\n'
        '  printf "%s" "unterminated"\n'
    )

    assert refs == []
    assert any(finding.rule_id == "SOURCE-PARSER-AMBIGUOUS" for finding in findings)


def test_top_level_call_to_defined_helper_keeps_source_parser_fail_closed():
    refs, findings = parse_pkgbuild(
        '_choose_sources() { source=("https://example.invalid/dynamic.tar"); }\n'
        '_choose_sources\n'
    )

    assert refs == []
    assert any(finding.rule_id == "SOURCE-PARSER-AMBIGUOUS" for finding in findings)


@pytest.mark.parametrize(
    "invocation",
    [
        "if _choose_sources; then :; fi",
        "! _choose_sources",
        "time _choose_sources",
        "MODE=test _choose_sources",
    ],
)
def test_control_wrapped_top_level_helper_calls_fail_closed(invocation: str):
    refs, findings = parse_pkgbuild(
        '_choose_sources() { source=("https://example.invalid/dynamic.tar"); }\n'
        + invocation
        + "\n"
    )

    assert refs == []
    assert any(finding.rule_id == "SOURCE-PARSER-AMBIGUOUS" for finding in findings)


def test_dynamic_top_level_command_selection_keeps_source_parser_fail_closed():
    refs, findings = parse_pkgbuild(
        '_choose_sources() { source=("https://example.invalid/dynamic.tar"); }\n'
        'selector=_choose_sources\n'
        '"$selector"\n'
    )

    assert refs == []
    assert any(finding.rule_id == "SOURCE-PARSER-AMBIGUOUS" for finding in findings)


@pytest.mark.parametrize(
    "mutation",
    [
        'builtin source helper.sh',
        'command eval "source=(dynamic.tar)"',
        'target=source\nprintf -v "$target" "%s" dynamic.tar',
        'target=source\nread "$target"',
        'target=source\nunset "$target"',
    ],
)
def test_indirect_top_level_source_mutation_builtins_fail_closed(mutation: str):
    refs, findings = parse_pkgbuild(
        'source=("https://example.invalid/static.tar")\n'
        + mutation
        + "\n"
    )

    assert refs == []
    assert any(finding.rule_id == "SOURCE-PARSER-AMBIGUOUS" for finding in findings)


def test_reject_ambiguous_dynamic_source_safely():
    refs, findings = parse_pkgbuild('source=("https://example.invalid/$(uname).tar.gz")\n')

    assert refs == []
    assert any(f.rule_id == "SOURCE-PARSER-AMBIGUOUS" for f in findings)


def test_reject_unsupported_scheme_safely():
    refs, _ = parse_pkgbuild('source=("git://example.invalid/repo.git")\nsha256sums=(SKIP)\n')

    assert refs[0].kind == SourceKind.unsupported


@pytest.mark.parametrize(
    ("source", "fragment_type"),
    [
        ("git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567", "commit"),
        ("git+https://example.invalid/repo.git#tag=v1.0", "tag"),
        ("git+https://example.invalid/repo.git#branch=main", "branch"),
        ("git+https://example.invalid/repo.git", None),
    ],
)
def test_classify_git_sources(source, fragment_type):
    refs, _ = parse_pkgbuild(f'source=("{source}")\nsha256sums=(SKIP)\n')

    assert refs[0].kind == SourceKind.git_https
    assert refs[0].fragment_type == fragment_type


def test_skip_on_https_archive_creates_manual_review_warning():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nsha256sums=(SKIP)\n')
    result = SourceAcquisitionResult(refs[0], status="failed")

    findings = ChecksumVerifier().verify(result)

    assert any(f.rule_id == "SOURCE-CHECKSUM-SKIP" and f.severity == Severity.HIGH and f.requires_manual_review for f in findings)


def test_skip_on_git_full_commit_creates_lower_warning():
    refs, _ = parse_pkgbuild('source=("git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567")\nsha256sums=(SKIP)\n')
    result = SourceAcquisitionResult(refs[0], status="skipped")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].severity == Severity.LOW


def test_skip_on_git_branch_creates_high_manual_review():
    refs, _ = parse_pkgbuild('source=("git+https://example.invalid/repo.git#branch=main")\nsha256sums=(SKIP)\n')
    result = SourceAcquisitionResult(refs[0], status="skipped")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].severity == Severity.HIGH
    assert findings[0].requires_manual_review is True


def test_checksum_match(tmp_path: Path):
    source = tmp_path / "src.tar.gz"
    source.write_text("hello")
    digest = hashlib.sha256(b"hello").hexdigest()
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, digest, "sha256", SourceKind.local)
    result = SourceAcquisitionResult(ref, source, size=5, sha256=digest, status="acquired")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MATCH"
    assert findings[0].requires_manual_review is False


def test_md5_checksum_match(tmp_path: Path):
    source = tmp_path / "src.tar.gz"
    source.write_text("hello")
    digest = hashlib.md5(b"hello").hexdigest()
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, digest, "md5", SourceKind.local)
    captured_sha256 = hashlib.sha256(b"hello").hexdigest()
    result = SourceAcquisitionResult(
        ref,
        source,
        size=5,
        sha256=captured_sha256,
        status="acquired",
    )

    findings = ChecksumVerifier().verify(result)

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MATCH"
    assert result.sha256 == captured_sha256
    assert result.sha256 != digest


def test_checksum_mismatch_blocks(tmp_path: Path):
    source = tmp_path / "src.tar.gz"
    source.write_text("hello")
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, "0" * 64, "sha256", SourceKind.local)
    result = SourceAcquisitionResult(ref, source, size=5, status="acquired")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MISMATCH"
    assert findings[0].blocks_installation is True


def test_missing_checksum_warning():
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.local)

    findings = ChecksumVerifier().verify(SourceAcquisitionResult(ref))

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MISSING"
    assert findings[0].requires_manual_review is True


def test_detached_sig_and_validpgpkeys_detected():
    refs, findings = parse_pkgbuild('source=("demo.tar.gz" "demo.tar.gz.sig")\nsha256sums=(SKIP SKIP)\nvalidpgpkeys=("ABCDEF")\n')

    assert refs[1].kind == SourceKind.signature
    assert any(f.rule_id == "SOURCE-VALIDPGPKEYS-DETECTED" for f in findings)


class FakeResponse:
    def __init__(self, body: bytes, final_url: str):
        self.body = body
        self.final_url = final_url
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def geturl(self):
        return self.final_url

    def read(self, size=-1):
        if self.offset >= len(self.body):
            return b""
        end = len(self.body) if size < 0 else min(len(self.body), self.offset + size)
        chunk = self.body[self.offset:end]
        self.offset = end
        return chunk


class FakeOpener:
    def __init__(self, body: bytes, final_url: str = "https://example.invalid/src.tar.gz"):
        self.body = body
        self.final_url = final_url
        self.calls = 0

    def open(self, request, timeout):
        self.calls += 1
        return FakeResponse(self.body, self.final_url)


class ExplodingOpener:
    def __init__(self):
        self.calls = 0

    def open(self, request, timeout):
        self.calls += 1
        raise AssertionError("offline mode attempted a network request")


def test_http_download_success_using_mocked_transport(tmp_path: Path):
    ref = SourceReference("https://example.invalid/src.tar.gz", "https://example.invalid/src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.http)
    fetcher = HttpSourceFetcher(SourcePolicy(max_download_size=100), opener=FakeOpener(b"hello"))

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "acquired"
    assert result.size == 5
    assert result.local_path.read_bytes() == b"hello"


def test_redirect_to_unsupported_scheme_rejected(tmp_path: Path):
    ref = SourceReference("https://example.invalid/src.tar.gz", "https://example.invalid/src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.http)
    fetcher = HttpSourceFetcher(SourcePolicy(max_download_size=100), opener=FakeOpener(b"hello", "file:///tmp/src.tar.gz"))

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "failed"
    assert any(f.rule_id == "SOURCE-HTTP-FETCH-FAILED" for f in result.findings)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/source.tar.gz",
        "http://[::1]/source.tar.gz",
        "http://169.254.169.254/latest/meta-data/",
        "https://localhost/source.tar.gz",
        "https://user:secret@example.invalid/source.tar.gz",
    ],
)
def test_http_source_refuses_local_or_credential_bearing_url_before_transport(tmp_path: Path, url: str):
    opener = FakeOpener(b"should not be read")
    ref = SourceReference(url, url, 0, "source.tar.gz", 0, None, None, SourceKind.http)

    result = HttpSourceFetcher(SourcePolicy(max_download_size=100), opener=opener).fetch(ref, tmp_path)

    assert opener.calls == 0
    assert result.status == "failed"
    assert any(f.rule_id == "SOURCE-HTTP-FETCH-FAILED" and f.blocks_installation for f in result.findings)


def test_http_source_refuses_redirect_to_non_public_address(tmp_path: Path):
    opener = FakeOpener(b"should not be stored", "http://169.254.169.254/latest/meta-data/")
    ref = SourceReference(
        "https://example.invalid/source.tar.gz",
        "https://example.invalid/source.tar.gz",
        0,
        "source.tar.gz",
        0,
        None,
        None,
        SourceKind.http,
    )

    result = HttpSourceFetcher(SourcePolicy(max_download_size=100), opener=opener).fetch(ref, tmp_path)

    assert opener.calls == 1
    assert result.status == "failed"
    assert not (tmp_path / "source.tar.gz").exists()


def test_source_report_redacts_url_credentials_query_and_fragment():
    ref = SourceReference(
        "renamed.tar::https://user:secret@example.invalid/source.tar?token=secret#fragment",
        "https://user:secret@example.invalid/source.tar?token=secret#fragment",
        0,
        "renamed.tar",
        0,
        None,
        None,
        SourceKind.http,
    )
    result = SourceAcquisitionResult(
        ref,
        final_url="https://user:secret@example.invalid/final?token=secret#fragment",
        status="failed",
    )

    payload = result.to_dict()

    serialized = repr(payload)
    assert "secret" not in serialized
    assert "token" not in serialized
    assert payload["original"] == "renamed.tar::https://example.invalid/source.tar"
    assert payload["resolved"] == "https://example.invalid/source.tar"
    assert payload["final_url"] == "https://example.invalid/final"


def test_oversized_download_rejected(tmp_path: Path):
    ref = SourceReference("https://example.invalid/src.tar.gz", "https://example.invalid/src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.http)
    fetcher = HttpSourceFetcher(SourcePolicy(max_download_size=3), opener=FakeOpener(b"hello"))

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "failed"
    assert result.local_path is None
    assert any(f.blocks_installation for f in result.findings)


def test_offline_http_fetch_makes_zero_transport_calls(tmp_path: Path):
    opener = ExplodingOpener()
    ref = SourceReference(
        "https://example.invalid/src.tar.gz",
        "https://example.invalid/src.tar.gz",
        0,
        "src.tar.gz",
        0,
        "SKIP",
        "sha256",
        SourceKind.http,
    )

    result = HttpSourceFetcher(SourcePolicy(offline=True), opener=opener).fetch(ref, tmp_path)

    assert opener.calls == 0
    assert result.status == "offline"
    assert any(f.rule_id == "SOURCE-OFFLINE-UNINSPECTED" and f.blocks_installation for f in result.findings)


def test_offline_git_fetch_makes_zero_runner_calls(tmp_path: Path):
    calls = []
    ref = SourceReference(
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        "commit",
        "0123456789abcdef0123456789abcdef01234567",
    )

    result = GitSourceFetcher(
        SourcePolicy(offline=True),
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
    ).fetch(ref, tmp_path)

    assert calls == []
    assert result.status == "offline"
    assert any(f.rule_id == "SOURCE-OFFLINE-UNINSPECTED" and f.blocks_installation for f in result.findings)


def test_offline_key_provider_makes_zero_transport_calls(tmp_path: Path):
    opener = ExplodingOpener()
    provider = TrustedKeyDirectoryProvider(
        SourcePolicy(offline=True, key_cache_dir=tmp_path / "keys"),
        opener=opener,
    )

    source = provider.get_key(FULL_FP)

    assert opener.calls == 0
    assert source.path is None
    assert source.error == "KEY_UNAVAILABLE"


def test_source_fetcher_propagates_offline_policy_to_signature_verifier(tmp_path: Path):
    fetcher = SourceFetcher(SourcePolicy(
        offline=True,
        auto_key_fetch=True,
        key_cache_dir=tmp_path / "keys",
    ))

    assert fetcher.signature_verifier.policy.offline is True
    assert fetcher.signature_verifier.key_provider.policy.offline is True


def test_source_fetcher_offline_bypasses_injected_http_and_git_fetchers(tmp_path: Path):
    class ExplodingFetcher:
        def __init__(self):
            self.calls = 0

        def fetch(self, ref, output_dir):
            self.calls += 1
            raise AssertionError("offline source acquisition called a transport")

    http_fetcher = ExplodingFetcher()
    git_fetcher = ExplodingFetcher()
    policy = SourcePolicy(
        offline=True,
        key_cache_dir=tmp_path / "keys",
    )
    refs = [
        SourceReference(
            "https://example.invalid/source.tar",
            "https://example.invalid/source.tar",
            0,
            "source.tar",
            0,
            "SKIP",
            "sha256",
            SourceKind.http,
        ),
        SourceReference(
            "git+https://example.invalid/repository.git",
            "git+https://example.invalid/repository.git",
            1,
            "repository",
            1,
            "SKIP",
            "sha256",
            SourceKind.git_https,
        ),
    ]
    fetcher = SourceFetcher(
        policy,
        http_fetcher=http_fetcher,
        git_fetcher=git_fetcher,
    )

    results = fetcher.acquire_all(refs, tmp_path)

    assert http_fetcher.calls == 0
    assert git_fetcher.calls == 0
    assert all(result.status == "offline" for result in results)
    assert all(any(f.blocks_installation for f in result.findings) for result in results)
    shutil.rmtree(fetcher.last_output_dir)


@pytest.mark.parametrize("value", ["../outside.tar", "/tmp/outside.tar"])
def test_local_source_paths_cannot_escape_package_root(tmp_path: Path, value: str):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (tmp_path / "outside.tar").write_bytes(b"outside")
    ref = SourceReference(value, value, 0, "outside.tar", 0, "SKIP", "sha256", SourceKind.local)
    fetcher = SourceFetcher(SourcePolicy(offline=True, max_download_size=100))

    result = fetcher.acquire_all([ref], pkg_dir)[0]

    assert result.status == "failed"
    assert result.local_path is None
    assert any(f.rule_id == "SOURCE-LOCAL-UNSAFE" and f.blocks_installation for f in result.findings)
    shutil.rmtree(fetcher.last_output_dir)


@pytest.mark.parametrize("reference_kind", [SourceKind.local, SourceKind.signature])
@pytest.mark.parametrize("kind", ["file_symlink", "directory_symlink", "directory", "fifo"])
def test_local_source_and_signature_reject_links_and_special_files(
    tmp_path: Path,
    kind: str,
    reference_kind: SourceKind,
):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    value = "source.tar"
    if kind == "file_symlink":
        outside = tmp_path / "outside.tar"
        outside.write_bytes(b"outside")
        (pkg_dir / value).symlink_to(outside)
    elif kind == "directory_symlink":
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / value).write_bytes(b"outside")
        (pkg_dir / "linked").symlink_to(outside, target_is_directory=True)
        value = f"linked/{value}"
    elif kind == "directory":
        (pkg_dir / value).mkdir()
    else:
        os.mkfifo(pkg_dir / value)
    ref = SourceReference(value, value, 0, "source.tar", 0, "SKIP", "sha256", reference_kind)
    fetcher = SourceFetcher(SourcePolicy(offline=True, max_download_size=100))

    result = fetcher.acquire_all([ref], pkg_dir)[0]

    assert result.status == "failed"
    assert any(f.rule_id == "SOURCE-LOCAL-UNSAFE" and f.blocks_installation for f in result.findings)
    shutil.rmtree(fetcher.last_output_dir)


def test_local_source_snapshot_is_bounded_and_independent(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    source = pkg_dir / "source.tar"
    source.write_bytes(b"stable")
    ref = SourceReference("source.tar", "source.tar", 0, "source.tar", 0, "SKIP", "sha256", SourceKind.local)
    fetcher = SourceFetcher(SourcePolicy(offline=True, max_download_size=6))

    result = fetcher.acquire_all([ref], pkg_dir)[0]
    source.write_bytes(b"changed")

    assert result.status == "acquired"
    assert result.local_path != source
    assert result.local_path.read_bytes() == b"stable"
    shutil.rmtree(fetcher.last_output_dir)


def test_local_source_changed_during_read_is_not_accepted(tmp_path: Path, monkeypatch):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    source = pkg_dir / "source.tar"
    source.write_bytes(b"a" * 70000)
    ref = SourceReference(
        "source.tar",
        "source.tar",
        0,
        "source.tar",
        0,
        "SKIP",
        "sha256",
        SourceKind.local,
    )
    fetcher = SourceFetcher(SourcePolicy(offline=True, max_download_size=100000))
    real_read = os.read
    reads = 0

    def replacing_read(fd, count):
        nonlocal reads
        payload = real_read(fd, count)
        reads += 1
        if reads == 1:
            source.write_bytes(b"b" * 70000)
        return payload

    monkeypatch.setattr("aurascan.core.source_acquisition.os.read", replacing_read)

    result = fetcher.acquire_all([ref], pkg_dir)[0]

    assert result.status == "failed"
    assert result.local_path is None
    assert any(f.rule_id == "SOURCE-LOCAL-UNSAFE" and f.blocks_installation for f in result.findings)
    shutil.rmtree(fetcher.last_output_dir)


def test_oversized_local_source_is_a_blocker(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "source.tar").write_bytes(b"too large")
    ref = SourceReference("source.tar", "source.tar", 0, "source.tar", 0, "SKIP", "sha256", SourceKind.local)
    fetcher = SourceFetcher(SourcePolicy(offline=True, max_download_size=3))

    result = fetcher.acquire_all([ref], pkg_dir)[0]

    assert result.status == "failed"
    assert any(f.rule_id == "SOURCE-LOCAL-UNSAFE" and f.blocks_installation for f in result.findings)
    shutil.rmtree(fetcher.last_output_dir)


class RoutedOpener:
    def open(self, request, timeout):
        body = b"first" if request.full_url.endswith("/first") else b"second"
        return FakeResponse(body, request.full_url)


def test_sources_with_the_same_filename_use_independent_destinations(tmp_path: Path):
    refs = [
        SourceReference("same.tar::https://example.invalid/first", "https://example.invalid/first", 0, "same.tar", 0, "SKIP", "sha256", SourceKind.http),
        SourceReference("same.tar::https://example.invalid/second", "https://example.invalid/second", 1, "same.tar", 1, "SKIP", "sha256", SourceKind.http),
    ]
    policy = SourcePolicy(max_download_size=100)
    fetcher = SourceFetcher(policy, http_fetcher=HttpSourceFetcher(policy, opener=RoutedOpener()))

    results = fetcher.acquire_all(refs, tmp_path)

    assert results[0].local_path != results[1].local_path
    assert results[0].local_path.read_bytes() == b"first"
    assert results[1].local_path.read_bytes() == b"second"
    shutil.rmtree(fetcher.last_output_dir)


def test_unsupported_source_is_a_fail_closed_blocker(tmp_path: Path):
    ref = SourceReference("git://example.invalid/repo", "git://example.invalid/repo", 0, "repo", 0, "SKIP", "sha256", SourceKind.unsupported)
    fetcher = SourceFetcher(SourcePolicy(offline=True))

    result = fetcher.acquire_all([ref], tmp_path)[0]

    assert result.status == "unsupported"
    assert any(f.rule_id == "SOURCE-UNSUPPORTED" and f.blocks_installation for f in result.findings)
    shutil.rmtree(fetcher.last_output_dir)


def test_signature_only_flow_reports_key_unavailable_when_pgp_key_missing():
    refs, parser_findings = parse_pkgbuild('source=("demo.tar.gz" "demo.tar.gz.sig")\nsha256sums=(SKIP SKIP)\nvalidpgpkeys=("ABCDEF")\n')

    fetcher = SourceFetcher()
    results = fetcher.acquire_all(refs, Path("/tmp/does-not-matter"))
    findings = parser_findings + [finding for result in results for finding in result.findings]

    assert any(f.rule_id in {"SOURCE-VALIDPGPKEY-WEAK", "KEY_UNAVAILABLE"} for f in findings)


def test_git_fetch_uses_isolated_home_and_disables_credentials(tmp_path: Path, monkeypatch):
    ref = SourceReference(
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        "commit",
        "0123456789abcdef0123456789abcdef01234567",
    )
    calls = []

    def fake_runner(args, **kwargs):
        calls.append((args, kwargs))
        if "clone" in args:
            Path(args[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/git")
    fetcher = GitSourceFetcher(runner=fake_runner)

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "acquired"
    assert all(call[1]["env"]["GIT_TERMINAL_PROMPT"] == "0" for call in calls)
    assert all(call[1]["env"]["GIT_CONFIG_NOSYSTEM"] == "1" for call in calls)
    assert all(call[1]["env"]["SSH_AUTH_SOCK"] == "" for call in calls)
    assert all("-c" in call[0] and "credential.helper=" in call[0] for call in calls)
    assert all(call[0][0] == "/usr/bin/git" for call in calls)


def test_git_fetch_refuses_path_shadowed_executable_before_runner(tmp_path: Path, monkeypatch):
    ref = SourceReference(
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        "commit",
        "0123456789abcdef0123456789abcdef01234567",
    )
    calls = []
    monkeypatch.setattr(
        "aurascan.core.source_acquisition.shutil.which",
        lambda _name: str(tmp_path / "shadowed-git"),
    )

    result = GitSourceFetcher(
        runner=lambda *args, **kwargs: calls.append((args, kwargs))
    ).fetch(ref, tmp_path)

    assert calls == []
    assert result.status == "skipped"
    assert any(f.rule_id == "SOURCE-GIT-UNAVAILABLE" and f.blocks_installation for f in result.findings)


def test_git_fetch_revalidates_executable_before_checkout(tmp_path: Path, monkeypatch):
    ref = SourceReference(
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        "commit",
        "0123456789abcdef0123456789abcdef01234567",
    )
    calls = []
    revalidations = 0

    def fake_runner(args, **kwargs):
        calls.append(args)
        if "clone" in args:
            Path(args[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(args, 0, "", "")

    def replacement_guard(_tool):
        nonlocal revalidations
        revalidations += 1
        if revalidations > 1:
            from aurascan.core.trusted_tools import TrustedToolError
            raise TrustedToolError("fixture replacement")

    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda _name: "/usr/bin/git")
    monkeypatch.setattr(
        "aurascan.core.source_acquisition.revalidate_trusted_system_tool",
        replacement_guard,
    )

    result = GitSourceFetcher(runner=fake_runner).fetch(ref, tmp_path)

    assert len(calls) == 1
    assert result.status == "failed"
    assert any(f.rule_id == "SOURCE-GIT-FETCH-FAILED" and f.blocks_installation for f in result.findings)


def test_git_fetch_refuses_non_public_url_before_runner(tmp_path: Path, monkeypatch):
    ref = SourceReference(
        "git+https://127.0.0.1/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        "git+https://127.0.0.1/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        "commit",
        "0123456789abcdef0123456789abcdef01234567",
    )
    calls = []
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/git")

    result = GitSourceFetcher(runner=lambda *args, **kwargs: calls.append((args, kwargs))).fetch(ref, tmp_path)

    assert calls == []
    assert result.status == "failed"
    assert any(f.rule_id == "SOURCE-GIT-FETCH-FAILED" and f.blocks_installation for f in result.findings)


FULL_FP = "0123456789ABCDEF0123456789ABCDEF01234567"
OTHER_FP = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"


def source_and_signature(tmp_path: Path, fingerprint: str = FULL_FP, sig_name: str = "src.tar.gz.sig"):
    source = tmp_path / "src.tar.gz"
    signature = tmp_path / sig_name
    key = tmp_path / f"{fingerprint}.asc"
    source.write_text("source")
    signature.write_text("signature")
    key.write_text("public key")
    source_ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, "SKIP", "sha256", SourceKind.local, validpgpkeys=[fingerprint])
    sig_ref = SourceReference(sig_name, sig_name, 1, sig_name, 1, "SKIP", "sha256", SourceKind.signature, validpgpkeys=[fingerprint])
    return source, signature, key, source_ref, sig_ref


class StaticKeyProvider:
    def __init__(self, path=None, fingerprint=FULL_FP, error=None):
        self.path = path
        self.fingerprint = fingerprint
        self.error = error
        self.requests = []

    def get_key(self, fingerprint):
        self.requests.append(fingerprint)
        if self.path:
            return PublicKeySource(fingerprint, self.path, "test")
        return PublicKeySource(fingerprint, error=self.error or "KEY_UNAVAILABLE")


def gpg_runner(status_fingerprint=FULL_FP, verify_returncode=0, calls=None):
    def runner(args, **kwargs):
        if calls is not None:
            calls.append((args, kwargs))
        if "--import" in args:
            return subprocess.CompletedProcess(args, 0, "[GNUPG:] IMPORT_OK 1 test\n", "")
        stdout = f"[GNUPG:] VALIDSIG {status_fingerprint} 2026-01-01 0 4 0 1 10 00 {status_fingerprint}\n"
        if verify_returncode != 0:
            stdout = "[GNUPG:] BADSIG BAD signer\n"
        return subprocess.CompletedProcess(args, verify_returncode, stdout, "")
    return runner


def test_full_fingerprint_normalization():
    assert PgpKeyNormalizer.normalize("0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567") == FULL_FP


def test_short_key_id_warning():
    refs, findings = parse_pkgbuild('source=("src.tar.gz" "src.tar.gz.sig")\nsha256sums=(SKIP SKIP)\nvalidpgpkeys=("89ABCDEF")\n')

    assert refs[0].validpgpkeys == ["89ABCDEF"]
    assert any(f.rule_id == "SOURCE-VALIDPGPKEY-WEAK" for f in findings)


def test_detached_asc_matched_to_source_archive(tmp_path: Path):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path, sig_name="src.tar.gz.asc")
    fetcher = SourceFetcher(signature_verifier=SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner()))

    results = fetcher.acquire_all([source_ref, sig_ref], tmp_path)

    assert results[0].pgp_verification["signature_path"] == "src.tar.gz.asc"
    assert any(f.rule_id == "SIGNATURE-VERIFIED" for f in results[0].findings)


def test_automatic_key_fetch_attempted_only_for_full_fingerprint(tmp_path: Path, monkeypatch):
    key_cache = tmp_path / "cache"
    provider = TrustedKeyDirectoryProvider(SourcePolicy(key_cache_dir=key_cache), opener=FakeOpener(b"public key"))

    source = provider.get_key(FULL_FP)

    assert source.path.exists()
    assert source.source_type == "keyserver"
    assert source.data == b"public key"
    assert oct(source.path.stat().st_mode & 0o777) == "0o600"


def test_automatic_key_fetch_refuses_non_public_redirect(tmp_path: Path):
    opener = FakeOpener(b"not a key", "http://169.254.169.254/latest/meta-data/")
    provider = TrustedKeyDirectoryProvider(
        SourcePolicy(key_cache_dir=tmp_path / "cache"),
        opener=opener,
    )

    source = provider.get_key(FULL_FP)

    assert source.path is None
    assert source.error == "KEY_FETCH_FAILED"
    assert not (tmp_path / "cache" / f"{FULL_FP}.asc").exists()


def test_automatic_key_fetch_not_attempted_for_short_key_ids(tmp_path: Path):
    provider = TrustedKeyDirectoryProvider(SourcePolicy(key_cache_dir=tmp_path / "cache"), opener=FakeOpener(b"public key"))

    source = provider.get_key("89ABCDEF")

    assert source.path is None
    assert source.error == "WEAK_KEY_ID"


def test_cached_key_is_reused_by_fingerprint(tmp_path: Path):
    cache = tmp_path / "cache"
    cache.mkdir()
    cached = cache / f"{FULL_FP}.asc"
    cached.write_text("public key")
    provider = TrustedKeyDirectoryProvider(SourcePolicy(key_cache_dir=cache), opener=FakeOpener(b"new key"))

    source = provider.get_key(FULL_FP)

    assert source.path == cached
    assert source.source_type == "cache"
    assert source.data == b"public key"


def test_key_cache_symlink_is_refused_without_read_or_overwrite(tmp_path: Path):
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("do not replace", encoding="utf-8")
    (cache / f"{FULL_FP}.asc").symlink_to(victim)
    opener = FakeOpener(b"new public key")

    source = TrustedKeyDirectoryProvider(
        SourcePolicy(key_cache_dir=cache),
        opener=opener,
    ).get_key(FULL_FP)

    assert source.path is None
    assert source.data is None
    assert source.error == "KEY_CACHE_UNSAFE"
    assert opener.calls == 0
    assert victim.read_text(encoding="utf-8") == "do not replace"


def test_symlinked_key_cache_directory_is_refused(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    cache = tmp_path / "cache"
    cache.symlink_to(target, target_is_directory=True)
    opener = FakeOpener(b"new public key")

    source = TrustedKeyDirectoryProvider(
        SourcePolicy(key_cache_dir=cache),
        opener=opener,
    ).get_key(FULL_FP)

    assert source.path is None
    assert source.error == "KEY_CACHE_UNSAFE"
    assert opener.calls == 0
    assert list(target.iterdir()) == []


def test_valid_signature_matching_fingerprint(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    calls = []
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner(calls=calls))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "valid"
    assert result.matched_validpgpkey is True
    assert any(f.rule_id == "SIGNATURE-VERIFIED" and not f.requires_manual_review for f in findings)
    assert all(call[1]["env"]["GNUPGHOME"] != os.environ.get("GNUPGHOME") for call in calls)
    assert all(call[0][0] == "/usr/bin/gpg" for call in calls)
    import_call = next(call for call in calls if "--import" in call[0])
    assert import_call[0][-1] != str(key)
    assert Path(import_call[0][-1]).name.startswith("key-")


def test_gpg_status_drops_user_ids_diagnostics_and_terminal_controls(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)

    def runner(args, **kwargs):
        if "--import" in args:
            return subprocess.CompletedProcess(
                args,
                0,
                f"[GNUPG:] IMPORT_OK 1 {FULL_FP}\n",
                "gpg: imported key from https://example.invalid/poison\x1b[31m\n",
            )
        status = (
            f"[GNUPG:] GOODSIG {FULL_FP} curl https://example.invalid/payload\x1b[2J\n"
            f"[GNUPG:] VALIDSIG {FULL_FP} 2026-01-01 0 4 0 1 10 00 {FULL_FP}\n"
            "[GNUPG:] NOTATION_DATA execute-this-command\n"
        )
        return subprocess.CompletedProcess(args, 0, status, "")

    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda _name: "/usr/bin/gpg")

    _findings, result = SignatureVerifier(
        key_provider=StaticKeyProvider(key),
        runner=runner,
    ).verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "valid"
    assert result.gpg_status == (
        f"IMPORT_OK {FULL_FP}\n"
        f"GOODSIG {FULL_FP}\n"
        f"VALIDSIG {FULL_FP}"
    )
    assert "curl" not in result.gpg_status
    assert "example.invalid" not in result.gpg_status
    assert "\x1b" not in result.gpg_status
    assert "NOTATION_DATA" not in result.gpg_status


def test_signature_key_is_snapshotted_before_gpg_import(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    imported_payloads = []

    def runner(args, **kwargs):
        if "--import" in args:
            key.write_text("replacement key", encoding="utf-8")
            imported_payloads.append(Path(args[-1]).read_text(encoding="utf-8"))
            return subprocess.CompletedProcess(args, 0, "[GNUPG:] IMPORT_OK 1 test\n", "")
        output = f"[GNUPG:] VALIDSIG {FULL_FP} 2026-01-01 0 4 0 1 10 00 {FULL_FP}\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda _name: "/usr/bin/gpg")

    findings, result = SignatureVerifier(
        key_provider=StaticKeyProvider(key),
        runner=runner,
    ).verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "valid"
    assert imported_payloads == ["public key"]
    assert any(item.rule_id == "SIGNATURE-VERIFIED" for item in findings)


def test_signature_verification_refuses_path_shadowed_gpg(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    calls = []
    verifier = SignatureVerifier(
        key_provider=StaticKeyProvider(key),
        runner=gpg_runner(calls=calls),
    )
    monkeypatch.setattr(
        "aurascan.core.source_acquisition.shutil.which",
        lambda _name: str(tmp_path / "shadowed-gpg"),
    )

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert calls == []
    assert result.verification_status == "gpg_unavailable"
    assert any(f.rule_id == "SIGNATURE-VERIFICATION-UNAVAILABLE" for f in findings)


def test_valid_signature_fingerprint_mismatch(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner(status_fingerprint=OTHER_FP))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "fingerprint_mismatch"
    assert any(f.rule_id == "SIGNATURE-FINGERPRINT-MISMATCH" and f.severity == Severity.HIGH for f in findings)


def test_invalid_signature_blocks(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner(verify_returncode=1))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "invalid"
    assert any(f.rule_id == "SIGNATURE-INVALID" and f.blocks_installation for f in findings)


def test_missing_public_key_creates_key_unavailable(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(None))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "key_unavailable"
    assert any(f.rule_id == "KEY_UNAVAILABLE" and f.requires_manual_review for f in findings)


def test_gpg_unavailable_creates_signature_verification_unavailable(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: None)

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "gpg_unavailable"
    assert any(f.rule_id == "SIGNATURE-VERIFICATION-UNAVAILABLE" for f in findings)


def test_signature_present_but_validpgpkeys_missing(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    source_ref.validpgpkeys = []
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "missing_validpgpkeys"
    assert any(f.rule_id == "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS" for f in findings)


def test_validpgpkeys_present_but_signature_missing():
    refs, findings = parse_pkgbuild(f'source=("src.tar.gz")\nsha256sums=(SKIP)\nvalidpgpkeys=("{FULL_FP}")\n')

    assert any(f.rule_id == "SIGNATURE-MISSING" for f in findings)


def test_skip_valid_signature_treated_better_than_skip_alone(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    fetcher = SourceFetcher(signature_verifier=SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner()))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    results = fetcher.acquire_all([source_ref, sig_ref], tmp_path)

    assert not any(f.rule_id == "SOURCE-CHECKSUM-SKIP" for f in results[0].findings)
    assert any(f.rule_id == "SIGNATURE-VERIFIED" for f in results[0].findings)


def test_skip_key_unavailable_remains_manual_review(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    fetcher = SourceFetcher(signature_verifier=SignatureVerifier(key_provider=StaticKeyProvider(None)))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    results = fetcher.acquire_all([source_ref, sig_ref], tmp_path)

    assert any(f.rule_id == "SOURCE-CHECKSUM-SKIP" and f.requires_manual_review for f in results[0].findings)
    assert any(f.rule_id == "KEY_UNAVAILABLE" for f in results[0].findings)
