"""Boundary, fold, whitespace and path helpers of the ported DetectionText."""

import pytest

from aurascan.analyzers.injection import injection_text as text


def test_fold_is_length_preserving_for_every_corpus_relevant_character():
    samples = ["A", "K", "\u212a", "\u0130", "\u0131", "s", "\u00df", "\u0301", "\u00bd", "-", "\u00a0"]
    for value in samples:
        folded = text.fold(value)
        assert len(folded) == len(value)
        assert text.fold(folded) == folded


def test_fold_does_not_casefold_expanding_characters():
    # str.casefold() would turn both of these into two characters and shift every later offset.
    assert text.fold("\u00df") == "\u00df"
    assert text.fold("\u0130") == "\u0130"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a", True),
        ("Z", True),
        ("_", True),
        ("7", True),
        ("\u00bd", False),  # No: str.isalnum() would say True, char.IsLetterOrDigit says False
        ("\u216b", False),  # Nl, likewise not a C# letter-or-digit
        ("\u0301", False),  # Mn is not a word character for the phrase predicate
        ("\u0301", False),
        ("-", False),
        (" ", False),
    ],
)
def test_phrase_word_char_matches_char_is_letter_or_digit(value, expected):
    assert text.is_phrase_word_char(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a", True),
        ("_", True),
        ("7", True),
        ("\u0301", True),  # .NET \w includes Mn
        ("\u203f", True),  # Pc
        ("\u00bd", False),
        ("-", False),
    ],
)
def test_regex_word_char_matches_dotnet_word_class(value, expected):
    assert text.is_regex_word_char(value) is expected


def test_both_predicates_treat_astral_code_points_as_non_word():
    # C# inspects a single char: for an astral neighbour that is a lone surrogate, and
    # char.IsLetterOrDigit(surrogate) is False. U+10400 is a letter to Python's str.isalpha().
    astral = "\U00010400"
    assert astral.isalpha() is True
    assert text.is_phrase_word_char(astral) is False
    assert text.is_regex_word_char(astral) is False


@pytest.mark.parametrize(
    "value, expected",
    [
        ("\t", True),
        ("\n", True),
        (" ", True),
        ("\u00a0", True),
        ("\u3000", True),
        ("\u001c", False),  # Python's isspace() says True; char.IsWhiteSpace says False
        ("\u180e", False),
        ("a", False),
    ],
)
def test_whitespace_set(value, expected):
    assert text.is_whitespace(value) is expected


def test_index_of_phrase_requires_clean_boundaries():
    assert text.index_of_phrase(text.fold("xx ignore previous instructions yy"), "ignore previous instructions", 0) == (3, 28)
    assert text.index_of_phrase(text.fold("xxignore previous instructions"), "ignore previous instructions", 0) == (-1, 0)
    assert text.index_of_phrase(text.fold("ignore previous instructions_yy"), "ignore previous instructions", 0) == (-1, 0)
    assert text.index_of_phrase(text.fold("ignore previous instructions.yy"), "ignore previous instructions", 0) == (0, 28)


def test_index_of_phrase_advances_by_one_on_a_rejected_hit():
    content = "aignore previous instructions ignore previous instructions"
    index, length = text.index_of_phrase(content, "ignore previous instructions", 0)
    assert index == 0 or index > 1
    assert content[index:index + length] == "ignore previous instructions"


def test_index_of_phrase_is_case_insensitive_without_moving_offsets():
    content = "IGNORE PREVIOUS INSTRUCTIONS"
    assert text.index_of_phrase(content, "ignore previous instructions", 0) == (0, 28)


def test_bound_collapses_whitespace_and_truncates():
    assert text.bound("a \t b\n\nc", 120) == "a b c"
    assert text.bound("  lead", 120) == "lead"
    assert text.bound("abcdef", 3) == "abc"
    assert text.bound("ab   ", 120) == "ab"
    assert text.bound("", 10) == ""


@pytest.mark.parametrize(
    "path, expected",
    [
        ("Assets/Corpus/Benign/Fixtures/SomeTests/Payload1.cs", True),
        ("a/Tests/b.cs", True),
        ("a/test/b.cs", True),
        ("a/editor-test/b.cs", True),
        ("a/FooTest.cs", True),
        ("a/Latest.cs", False),
        ("a/Contest.cs", False),
        ("", False),
    ],
)
def test_is_test_fixture_path(path, expected):
    assert text.is_test_fixture_path(path) is expected


def test_lowercase_test_stem_needs_a_non_word_separator():
    # C# IsTestFileName accepts a leading "test" word only when the next char is not a word char,
    # so test_helpers.cs is not a test file but test-helpers.cs is.
    assert text.is_test_fixture_path("a/test_helpers.cs") is False
    assert text.is_test_fixture_path("a/test-helpers.cs") is True


@pytest.mark.parametrize(
    "path, expected",
    [
        ("README.md", True),
        ("a/B.txt", True),
        ("a/b.html", True),
        ("a/b.htm", True),
        ("a/b.rst", True),
        ("a/b.adoc", True),
        ("a/b.md.bak", False),
        ("a/b.cs", False),
    ],
)
def test_is_documentation_path(path, expected):
    assert text.is_documentation_path(path) is expected


def test_is_suppressed_matches_exact_file_or_folder_prefix():
    assert text.is_suppressed("Assets/Vendor/a.md", ("Assets/Vendor",)) is True
    assert text.is_suppressed("Assets/Vendor/a.md", ("./Assets/Vendor/",)) is True
    assert text.is_suppressed("Assets/VendorX/a.md", ("Assets/Vendor",)) is False
    assert text.is_suppressed("Assets/VendorX/a.md", ()) is False
