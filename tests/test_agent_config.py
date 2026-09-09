"""TOML fixtures are inert text; no referenced path or command is used."""

import pytest

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from aurascan.core.agent_config import (
    AgentConfigError,
    CodeWhaleConfig,
    parse_codewhale_config,
)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "# allow_shell = true\n# instructions = ['../outside.md']\n",
        "allow_shell = false\n",
        "allow_shell = true # explicit setting\n",
        "'allow_shell' = true\n",
        '"allow\\u005fshell" = true\n',
        "instructions = []\n",
        "instructions = ['AGENTS.md', 'docs/policy.md',]\n",
        'instructions = ["\\u002e\\u002e/notes.md", "\\U0001f40b.md"]\n',
        'note = "allow_shell = true\\ninstructions = [\'../outside.md\']"\n',
        "note = 'allow_shell = true'\nallow_shell = false\n",
        "[tools]\nallow_shell = true\ninstructions = ['../outside.md']\n",
        "allow_shell = false\n[tools]\nallow_shell = true\n",
        '["tools"]\n"allow_shell" = true\n',
        "[providers.local]\nname = 'example'\n[providers]\nactive = 'local'\n",
        "[providers . 'local']\nallow_shell = true\n",
        '"tools.allow_shell" = true\n',
        "'' = 'empty quoted key'\n",
        'model = "example"\nbase_url = "https://example.invalid"\ntimeout = 30\n',
        "temperature = 0.25\nratio = 1e-2\nwindow = 1_024\n",
        "a = -42\nb = +42\nc = 0x2a\nd = 0o52\ne = 0b10_1010\n",
        "a = -0.0\nb = +inf\nc = nan\nd = 6.626e-34\n",
        "options = [true, 2, 'three', [4, 'five']]\n",
        "# sample\r\nallow_shell = true\r\ninstructions = ['AGENTS.md']\r\n",
        'note = "# not a comment \\"\"\n',
    ],
)
def test_supported_subset_matches_toml_top_level_meaning(text):
    reference = tomllib.loads(text)

    inspected = parse_codewhale_config(text)

    assert inspected.allow_shell is reference.get("allow_shell", False)
    assert tuple(path for path, _line in inspected.instructions) == tuple(
        reference.get("instructions", ())
    )
    assert inspected.allow_shell_line > 0 if "allow_shell" in reference else (
        inspected.allow_shell_line == 0
    )


def test_multiline_array_preserves_physical_lines_and_decodes_paths():
    text = (
        "# inert configuration\r\n"
        "  allow_shell = true\r\n"
        "instructions = [\r\n"
        "  # references below are text only\r\n"
        '  "\\u002e\\u002e/outside.md",\r\n'
        "  'docs\\literal.md', # the backslash stays literal\r\n"
        '  "notes/#not-a-comment.md",\r\n'
        "]\r\n"
    )

    assert parse_codewhale_config(text) == CodeWhaleConfig(
        allow_shell=True,
        allow_shell_line=2,
        instructions=(
            ("../outside.md", 5),
            ("docs\\literal.md", 6),
            ("notes/#not-a-comment.md", 7),
        ),
    )


@pytest.mark.parametrize(
    "text",
    [
        "allow_shell = true\nallow_shell = false\n",
        'allow_shell = true\n"allow_shell" = false\n',
        '"allow\\u005fshell" = true\nallow_shell = false\n',
        "instructions = []\ninstructions = []\n",
        "[tools]\nmode = true\n[tools]\nmode = false\n",
        "[tools]\nmode = true\n[tools.mode]\nname = 'example'\n",
        "[tools.mode]\nname = 'example'\n[tools]\nmode = true\n",
        "tools = true\n[tools.mode]\nname = 'example'\n",
        "[providers.local]\n[providers]\n[providers]\n",
        "allow_shell = True\n",
        "allow_shell = true;\n",
        "allow_shell = true false\n",
        "allow_shell =\ntrue\n",
        "allow_shell = # no value\n",
        "= true\n",
        "allow_shell true\n",
        "allow shell = true\n",
        "instructions = ['a.md' 'b.md']\n",
        "instructions = ['a.md',, 'b.md']\n",
        "instructions = [\n'a.md'\n'b.md'\n]\n",
        "instructions = ['unterminated]\n",
        "instructions = ['a.md'\n",
        'instructions = ["a\\uD800.md"]\n',
        'instructions = ["a\\U00110000.md"]\n',
        'instructions = ["a\\u00qq.md"]\n',
        'instructions = ["a\n.md"]\n',
        'instructions = ["a.md""b.md"]\n',
        "[tools\nallow_shell = true\n",
        "[tools..local]\nallow_shell = true\n",
        "[tools.]\nallow_shell = true\n",
        "[tools] allow_shell = true\n",
        "a = 01\n",
        "a = +0x2a\n",
        "a = 1__0\n",
        "a = 1_\n",
        "a = _1\n",
        "a = 1.\n",
        "a = .1\n",
        "a = 1.e3\n",
        "a = 00.1\n",
        "a = null\n",
        "a = TRUE\n",
        "a = false\rallow_shell = true\n",
        "# control\x01\nallow_shell = true\n",
        'note = "control\x7f"\n',
        'note = "control\x00"\n',
    ],
)
def test_invalid_toml_fails_without_accepting_partial_settings(text):
    with pytest.raises(tomllib.TOMLDecodeError):
        tomllib.loads(text)
    with pytest.raises(AgentConfigError):
        parse_codewhale_config(text)


def test_extended_hex_escape_is_explicit_coverage_failure():
    # TOML 1.1 readers accept this escape; older tomllib readers reject it.
    # AuraScan's bounded subset must refuse it independently of that oracle.
    with pytest.raises(AgentConfigError):
        parse_codewhale_config('instructions = ["a\\x2e.md"]\n')


@pytest.mark.parametrize(
    "text",
    [
        'allow_shell = "true"\n',
        "allow_shell = 1\n",
        "allow_shell = [true]\n",
        "instructions = 'AGENTS.md'\n",
        "instructions = true\n",
        "instructions = [1]\n",
        "instructions = [['AGENTS.md']]\n",
        "[allow_shell]\nvalue = true\n",
        "[instructions]\npath = 'AGENTS.md'\n",
        "[instructions.nested]\npath = 'AGENTS.md'\n",
    ],
)
def test_wrong_top_level_setting_types_are_incomplete_coverage(text):
    tomllib.loads(text)
    with pytest.raises(AgentConfigError):
        parse_codewhale_config(text)


@pytest.mark.parametrize(
    "text",
    [
        "tools.allow_shell = true\n",
        "tools = { allow_shell = true }\n",
        "[[tools]]\nallow_shell = true\n",
        'note = """allow_shell = true"""\n',
        "note = '''allow_shell = true'''\n",
        "created = 2026-09-09\n",
        "created = 2026-09-09T01:02:03Z\n",
        "created = 01:02:03\n",
    ],
)
def test_unsupported_valid_toml_is_explicit_coverage_failure(text):
    tomllib.loads(text)
    with pytest.raises(AgentConfigError):
        parse_codewhale_config(text)


def test_errors_never_copy_inert_source_or_fake_secret():
    text = "allow_shell = true\nsecret = 'FAKE_TOKEN_FOR_TEST_ONLY'\ninvalid\n"

    with pytest.raises(AgentConfigError) as captured:
        parse_codewhale_config(text)

    assert captured.value.line_number == 3
    assert str(captured.value) == (
        "Agent configuration is malformed, unsupported, or exceeds inspection bounds."
    )
    assert "FAKE_TOKEN" not in repr(captured.value)
    assert "invalid" not in str(captured.value)


@pytest.mark.parametrize(
    "text",
    [
        "#" * (1024 * 1024 + 1),
        "#" + "\U0001f40b" * (256 * 1024),
        'note = "' + "a" * 65537 + '"\n',
        '"' + "k" * 129 + '" = true\n',
        "k" * 129 + " = true\n",
        "instructions = [" + ",".join("'a.md'" for _ in range(257)) + "]\n",
        "value = " + "[" * 10 + "0" + "]" * 10 + "\n",
        "[" + ".".join("part" for _ in range(9)) + "]\n",
        "\n".join("key{} = true".format(index) for index in range(4097)),
        "\n".join(
            "key{} = [{}]".format(index, ",".join("1" for _ in range(256)))
            for index in range(17)
        ),
        "number = " + "1" * 129 + "\n",
        'note = "\ud800"\n',
    ],
)
def test_size_structure_and_decoding_limits_fail_closed(text):
    with pytest.raises(AgentConfigError):
        parse_codewhale_config(text)


def test_large_comment_is_bounded_without_hiding_active_settings():
    text = "#" + "a" * (1024 * 1024 - 25) + "\nallow_shell = true\n"

    assert parse_codewhale_config(text).allow_shell is True


def test_input_type_is_not_coerced_into_configuration():
    with pytest.raises(AgentConfigError):
        parse_codewhale_config(b"allow_shell = true")
