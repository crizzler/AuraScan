"""Tests for the bounded PKGBUILD build-dependency reader."""

import pytest

from aurascan.core.pkgbuild_dependencies import (
    declared_build_dependencies,
    dependency_token_valid,
)


def test_multiline_literal_arrays_are_collected_in_order():
    content = (
        "pkgname=demo\n"
        "depends=(\n"
        "  lib32-gcc-libs\n"
        "  lib32-glibc\n"
        ")\n"
        "makedepends=(\n"
        "  cmake\n"
        "  lib32-jack\n"
        ")\n"
    )

    assert declared_build_dependencies(content) == (
        "lib32-gcc-libs",
        "lib32-glibc",
        "cmake",
        "lib32-jack",
    )


def test_inline_arrays_quotes_comments_and_appends_are_supported():
    content = (
        "makedepends=(cmake 'git' \"lib32-glibc>=2.38\") # trailing comment\n"
        "makedepends+=(ninja\n"
        "  # an inner comment line\n"
        "  lib32-libpulse # glued comment\n"
        ")\n"
    )

    assert declared_build_dependencies(content) == (
        "cmake",
        "git",
        "lib32-glibc>=2.38",
        "ninja",
        "lib32-libpulse",
    )


def test_scalar_form_is_supported():
    assert declared_build_dependencies("depends=lib32-glibc\n") == (
        "lib32-glibc",
    )


def test_irrelevant_content_before_functions_is_ignored():
    content = (
        "pkgname=demo\n"
        "pkgver=1\n"
        "pkgdesc=\"A demo: with a colon and 'quotes'\"\n"
        "source=(\"git+https://example.invalid/demo.git\")\n"
        "options=(!strip)\n"
        "checkdepends=(python-pytest)\n"
    )

    assert declared_build_dependencies(content) == ("python-pytest",)


def test_assignments_inside_functions_are_not_build_metadata():
    content = (
        "makedepends=(cmake)\n"
        "\n"
        "package_demo() {\n"
        "  optdepends=('extra: feature')\n"
        "  depends+=(lib32-glibc)\n"
        "}\n"
    )

    assert declared_build_dependencies(content) == ("cmake",)


def test_first_function_stops_declaration_scanning():
    content = (
        "build() {\n"
        "  :\n"
        "}\n"
        "makedepends=(ninja)\n"
    )

    assert declared_build_dependencies(content) == ()


@pytest.mark.parametrize(
    "content",
    (
        "makedepends=(${_deps[@]})\n",
        "makedepends=($(echo cmake))\n",
        "makedepends=(\"$pkgname-tools\")\n",
        "makedepends=($EXTRA cmake)\n",
        "depends=(cmake\n",
        "makedepends=(!strip)\n",
        "makedepends=('cmake)\n",
        "makedepends=(cmake; rm -rf /)\n",
        "makedepends=(cmake 'injected value')\n",
        "depends=($'cmake')\n",
        "depends=\"cmake extra\"\n",
        "depends=word=\n",
    ),
)
def test_unsupported_forms_report_unknown(content):
    assert declared_build_dependencies(content) is None


def test_dynamic_append_with_dollar_is_unknown():
    assert declared_build_dependencies("makedepends+=(cmake \"$_extra\")\n") is None


def test_oversized_and_non_string_input_is_unknown():
    assert declared_build_dependencies(None) is None
    assert declared_build_dependencies(123) is None
    assert declared_build_dependencies("") is None
    assert declared_build_dependencies("makedepends=(cmake)\n" * 40000) is None


def test_dependency_token_validation():
    assert dependency_token_valid("lib32-glibc") is True
    assert dependency_token_valid("lib32-glibc>=2.38") is True
    assert dependency_token_valid("python_pytest") is True
    assert dependency_token_valid("Lib32-Glibc") is False
    assert dependency_token_valid("cmake extra") is False
    assert dependency_token_valid("$(echo cmake)") is False
    assert dependency_token_valid("") is False
