"""Bounded, data-only inspection of CodeWhale's project TOML settings.

This deliberately supports a strict TOML subset rather than depending on a
runtime TOML package (AuraScan supports Python 3.8). Unsupported syntax is an
inspection failure, never a reason to infer that execution is disabled. No
setting is applied and no referenced path is opened here.
"""

import re
from dataclasses import dataclass
from typing import Tuple


_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_STRING_CHARS = 65536
_MAX_KEY_CHARS = 128
_MAX_DECLARATIONS = 4096
_MAX_VALUES = 4096
_MAX_ARRAY_ITEMS = 256
_MAX_DEPTH = 8
_MAX_SCALAR_CHARS = 128
_BARE_KEY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_DECIMAL = r"(?:0|[1-9](?:_?[0-9])*)"
_INTEGER = re.compile(
    r"(?:[+-]?" + _DECIMAL
    + r"|0x[0-9a-fA-F](?:_?[0-9a-fA-F])*"
    + r"|0o[0-7](?:_?[0-7])*|0b[01](?:_?[01])*)\Z"
)
_FLOAT = re.compile(
    r"[+-]?(?:inf|nan|" + _DECIMAL
    + r"(?:\.[0-9](?:_?[0-9])*(?:[eE][+-]?[0-9](?:_?[0-9])*)?"
    + r"|[eE][+-]?[0-9](?:_?[0-9])*))\Z"
)
_NUMBER = object()
_ESCAPES = {
    "b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r",
    '"': '"', "\\": "\\",
}


class AgentConfigError(ValueError):
    """A fixed, secret-free failure with an optional physical source line."""

    def __init__(self, line_number=0):
        self.line_number = max(0, min(int(line_number), _MAX_CONFIG_BYTES + 1))
        super().__init__(
            "Agent configuration is malformed, unsupported, or exceeds inspection bounds."
        )


@dataclass(frozen=True)
class CodeWhaleConfig:
    allow_shell: bool = False
    allow_shell_line: int = 0
    instructions: Tuple[Tuple[str, int], ...] = ()


@dataclass(frozen=True)
class _Value:
    value: object
    line_number: int


class _Parser:
    def __init__(self, text):
        self.text = text
        self.position = 0
        self.line = 1
        self.declarations = 0
        self.values = 0
        self.table = ()
        self.tables = set()
        self.explicit_tables = set()
        self.keys = set()
        self.allow_shell = False
        self.allow_shell_line = 0
        self.instructions = ()

    def _fail(self, line_number=None):
        raise AgentConfigError(self.line if line_number is None else line_number)

    def _peek(self):
        return self.text[self.position:self.position + 1]

    def _horizontal_space(self):
        while self._peek() in (" ", "\t"):
            self.position += 1

    def _comment(self):
        if self._peek() == "#":
            end = self.text.find("\n", self.position)
            self.position = len(self.text) if end < 0 else end

    def _space(self):
        while True:
            self._horizontal_space()
            self._comment()
            if self._peek() != "\n":
                return
            self.position += 1
            self.line += 1

    def _end_statement(self):
        self._horizontal_space()
        self._comment()
        if self._peek() not in ("", "\n"):
            self._fail()

    def _string(self):
        quote = self._peek()
        if self.text.startswith(quote * 3, self.position):
            # Multiline strings have separate newline/escape semantics.
            self._fail()
        self.position += 1
        characters = []
        while self.position < len(self.text):
            character = self._peek()
            self.position += 1
            if character == quote:
                return "".join(characters)
            if character == "\n":
                self._fail()
            if character == "\\" and quote == '"':
                escape = self._peek()
                self.position += 1
                if escape in _ESCAPES:
                    character = _ESCAPES[escape]
                elif escape in ("u", "U"):
                    width = 4 if escape == "u" else 8
                    digits = self.text[self.position:self.position + width]
                    if len(digits) != width or any(c not in _HEX_CHARS for c in digits):
                        self._fail()
                    codepoint = int(digits, 16)
                    if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                        self._fail()
                    character = chr(codepoint)
                    self.position += width
                else:
                    self._fail()
            characters.append(character)
            if len(characters) > _MAX_STRING_CHARS:
                self._fail()
        self._fail()

    def _key(self):
        if self._peek() in ('"', "'"):
            key = self._string()
        else:
            start = self.position
            while self._peek() in _BARE_KEY_CHARS:
                self.position += 1
                if self.position - start > _MAX_KEY_CHARS:
                    self._fail()
            key = self.text[start:self.position]
            if not key:
                self._fail()
        if len(key) > _MAX_KEY_CHARS:
            self._fail()
        return key

    def _value(self, depth=0):
        self.values += 1
        if self.values > _MAX_VALUES or depth > _MAX_DEPTH:
            self._fail()
        line = self.line
        character = self._peek()
        if character in ('"', "'"):
            return _Value(self._string(), line)
        if character == "[":
            self.position += 1
            items = []
            self._space()
            while self._peek() != "]":
                if len(items) >= _MAX_ARRAY_ITEMS:
                    self._fail()
                items.append(self._value(depth + 1))
                self._space()
                if self._peek() == ",":
                    self.position += 1
                    self._space()
                elif self._peek() != "]":
                    self._fail()
            self.position += 1
            return _Value(tuple(items), line)
        start = self.position
        while self._peek() and self._peek() not in " \t\n,#]":
            self.position += 1
            if self.position - start > _MAX_SCALAR_CHARS:
                self._fail()
        token = self.text[start:self.position]
        if token in ("true", "false"):
            return _Value(token == "true", line)
        if _INTEGER.fullmatch(token) or _FLOAT.fullmatch(token):
            # Ordinary numeric options are validated, not interpreted.
            return _Value(_NUMBER, line)
        self._fail()

    def _header(self):
        self.position += 1
        self._horizontal_space()
        parts = []
        while True:
            parts.append(self._key())
            if len(parts) > _MAX_DEPTH:
                self._fail()
            self._horizontal_space()
            if self._peek() != ".":
                break
            self.position += 1
            self._horizontal_space()
        if self._peek() != "]":
            self._fail()
        self.position += 1
        table = tuple(parts)
        if table in self.explicit_tables or table[0] in ("allow_shell", "instructions"):
            self._fail()
        for length in range(1, len(table) + 1):
            prefix = table[:length]
            if prefix in self.keys:
                self._fail()
            self.tables.add(prefix)
        self.explicit_tables.add(table)
        self.table = table

    def _assignment(self):
        line = self.line
        key = self._key()
        self._horizontal_space()
        if self._peek() != "=":
            # Dotted assignments and inline tables are unsupported rather than
            # approximated; they can change the meaning of a later setting.
            self._fail()
        self.position += 1
        self._horizontal_space()
        value = self._value()
        path = self.table + (key,)
        if path in self.keys or path in self.tables:
            self._fail(line)
        self.keys.add(path)
        if not self.table and key == "allow_shell":
            if type(value.value) is not bool:
                self._fail(line)
            self.allow_shell = value.value
            self.allow_shell_line = line
        elif not self.table and key == "instructions":
            if not isinstance(value.value, tuple):
                self._fail(line)
            if any(not isinstance(item.value, str) for item in value.value):
                self._fail(line)
            self.instructions = tuple(
                (item.value, item.line_number) for item in value.value
            )

    def parse(self):
        self._space()
        while self.position < len(self.text):
            self.declarations += 1
            if self.declarations > _MAX_DECLARATIONS:
                self._fail()
            if self._peek() == "[":
                self._header()
            else:
                self._assignment()
            self._end_statement()
            self._space()
        return CodeWhaleConfig(
            self.allow_shell, self.allow_shell_line, self.instructions
        )


def parse_codewhale_config(text: str) -> CodeWhaleConfig:
    """Inspect effective top-level settings without applying configuration.

    Supported syntax consists of bare/quoted keys, single-line basic/literal
    strings (including Unicode escapes), booleans, ordinary numbers, bounded
    arrays, comments, and tables with simple or dotted names. Dotted key
    assignments, inline tables, arrays of tables, multiline strings, and date
    or time values produce explicit incomplete inspection. Invalid or duplicate
    declarations and incorrect types for the two inspected settings also fail.
    """
    if not isinstance(text, str) or len(text) > _MAX_CONFIG_BYTES:
        raise AgentConfigError()
    try:
        if len(text.encode("utf-8")) > _MAX_CONFIG_BYTES:
            raise AgentConfigError()
    except UnicodeEncodeError:
        raise AgentConfigError() from None
    line = 1
    for position, character in enumerate(text):
        if character == "\n":
            line += 1
        elif character == "\r":
            if text[position + 1:position + 2] != "\n":
                raise AgentConfigError(line)
        elif (ord(character) < 32 and character != "\t") or character == "\x7f":
            raise AgentConfigError(line)
    return _Parser(text.replace("\r\n", "\n")).parse()
