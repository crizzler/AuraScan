"""Bounded static extraction of PKGBUILD build-dependency declarations.

This module is a conservative text reader, not a Bash evaluator and not a
policy engine.  It reports the literal ``depends``/``makedepends``/
``checkdepends`` values a PKGBUILD declares at top level so the guided AUR
update flow can explain, before any build, which declared dependencies the
build step could not install.  It never decides whether a build may run, never
executes the file, and returns ``None`` (unknown) whenever the declaration set
cannot be proven from plain literals - an unknown result disables the advisory
check instead of producing a partial claim.

Only a small supported subset is accepted:

* a top-level assignment at column zero in ``key=(...)``, ``key+=(...)`` or
  ``key=word`` form, with comments and quoted or bare literal words;
* nothing dynamic: ``$`` expansions, command substitutions, subscripts,
  ``eval``/``source``, or assignments indented inside functions, loops or
  conditionals are all reported as unknown.
"""

import re
from typing import List, Optional, Sequence, Tuple


DEPENDENCY_ARRAY_KEYS = ("depends", "makedepends", "checkdepends")
MAX_PKGBUILD_BYTES = 1024 * 1024
MAX_BUILD_DEPENDENCIES = 64
MAX_ARRAY_CHARS = 8192

_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9@._+-]{0,199}$")
_CONSTRAINT_RE = re.compile(
    r"^([a-z0-9][a-z0-9@._+-]{0,199})(>=|<=|==|=|>|<)([a-zA-Z0-9._+~:-]{1,64})$"
)
_ASSIGNMENT_RE = re.compile(r"^(depends|makedepends|checkdepends)(\+?=)(.*)$")
_FUNCTION_START_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*[ \t]*\(\)[ \t]*\{?[ \t]*$")


def dependency_token_valid(token: str) -> bool:
    """Whether one dependency token is a supported literal requirement."""

    candidate = str(token or "").strip()
    return bool(
        _PACKAGE_NAME_RE.fullmatch(candidate)
        or _CONSTRAINT_RE.fullmatch(candidate)
    )


def declared_build_dependencies(content: object) -> Optional[Tuple[str, ...]]:
    """Return the declared build dependencies, or ``None`` when unknown.

    ``None`` means "do not make claims about this package": the caller must
    skip its advisory dependency check entirely rather than reporting a
    partial list.
    """

    if not isinstance(content, str) or not content:
        return None
    if len(content.encode("utf-8", "replace")) > MAX_PKGBUILD_BYTES:
        return None

    lines = content.splitlines()
    collected: List[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if _FUNCTION_START_RE.match(line):
            # Declarations after the first function definition are not part of
            # the top-level build metadata this check models.
            break
        match = _ASSIGNMENT_RE.match(line)
        if match is None:
            index += 1
            continue
        remainder = match.group(3).strip()
        if remainder.startswith("("):
            body, consumed = _array_body(lines, index, remainder)
            if body is None:
                return None
            tokens = _literal_tokens(_strip_comments(body))
            if tokens is None:
                return None
            collected.extend(tokens)
            index += consumed
        else:
            token = _literal_scalar(remainder)
            if token is None:
                return None
            collected.append(token)
            index += 1
        if len(collected) > MAX_BUILD_DEPENDENCIES:
            return None

    for token in collected:
        if not dependency_token_valid(token):
            return None
    return tuple(collected)


def _array_body(
    lines: Sequence[str],
    start: int,
    remainder: str,
) -> Tuple[Optional[str], int]:
    """Read one parenthesized array body starting at ``start``.

    Returns the body text (without the outer parentheses) and the number of
    lines consumed, or ``(None, 0)`` for anything malformed or oversized.
    """

    body: List[str] = []
    quote = ""
    depth = 0
    index = start
    text = remainder
    position = 0
    total = 0
    while True:
        while position < len(text):
            character = text[position]
            if quote:
                if character == quote:
                    quote = ""
                body.append(character)
                position += 1
                continue
            if character in {"'", '"'}:
                quote = character
                position += 1
                body.append(character)
                continue
            if character == "(":
                if depth >= 1:
                    body.append(character)
                    total += 1
                depth += 1
                position += 1
                continue
            if character == ")":
                depth -= 1
                if depth == 0:
                    return "".join(body), index - start + 1
                body.append(character)
                total += 1
                position += 1
                continue
            body.append(character)
            total += 1
            position += 1
        if total > MAX_ARRAY_CHARS:
            return None, 0
        index += 1
        if index >= len(lines):
            return None, 0
        text = "\n" + lines[index]
        position = 0


def _strip_comments(text: str) -> str:
    """Remove newline-bounded comments while preserving line structure."""

    output: List[str] = []
    quote = ""
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if quote:
            output.append(character)
            if character == quote:
                quote = ""
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(character)
            index += 1
            continue
        if character == "#" and (index == 0 or text[index - 1].isspace()):
            while index < length and text[index] != "\n":
                index += 1
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _literal_tokens(body: str) -> Optional[List[str]]:
    tokens: List[str] = []
    index = 0
    length = len(body)
    while index < length:
        character = body[index]
        if character.isspace():
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            start = index
            while index < length and body[index] != quote:
                index += 1
            if index >= length:
                return None
            token = body[start:index]
            index += 1
            if quote == '"' and any(marker in token for marker in ("$", "`", "\\")):
                return None
        else:
            start = index
            while index < length and not body[index].isspace():
                index += 1
            token = body[start:index]
            if any(
                marker in token
                for marker in ("$", "`", "\\", "'", '"', "#", "(", ")", "!", "[", "]")
            ):
                return None
        if not token:
            return None
        tokens.append(token)
    return tokens


def _literal_scalar(remainder: str) -> Optional[str]:
    text = _strip_comments(remainder).strip()
    if not text:
        return None
    if text[0] in {"'", '"'}:
        quote = text[0]
        if len(text) < 2 or not text.endswith(quote):
            return None
        inner = text[1:-1]
        if quote == '"' and any(marker in inner for marker in ("$", "`", "\\")):
            return None
        return inner
    if any(marker in text for marker in ("$", "`", "\\", "'", '"', "#", "(", ")")):
        return None
    return text
