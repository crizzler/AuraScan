# AuraScan Unreleased

Changes after v0.15.1:

- None yet.
- Repository-provenance analysis now tracks an assignment that follows a leading
  shell control keyword inside one segment. A single-line loop body
  (`for f in a; do lang=...; install "d/$lang" x; done`) previously lost the
  assignment, so taint was dropped and a stale constant could fabricate an
  inspected path with `complete=True`; that shape now fails closed exactly like
  its multi-line spelling. Assignments that precede a command name (`x=1 install
  ...`) remain untracked, and control-prefixed `declare -n` namerefs remain
  tainted. Package-scanner rule version advances to `1.16.0`, invalidating cached
  results from earlier rule versions.
- Repository-provenance analysis now resolves a bounded set of side-effect-free
  parameter expansions over constants it has already proven: `${name}`, literal
  `#`/`##`/`%`/`%%` trims, literal `/`/`//` substitutions, and
  `${name:-word}`/`${name+word}` whose name is known. A path built from such a
  literal value is no longer left as unresolved taint, while assignment
  (`:=`/`=`), subscript, substring-offset, indirection, nested and glob-pattern
  forms stay fail closed and unchanged. Package-scanner rule version advances to
  `1.17.0`, invalidating cached results from earlier rule versions.
- Repository-provenance analysis now masks `&`, `|` and newline inside bounded
  `[[ … ]]` compound spans before the shared segmenter sees the text, so a
  compound conditional parses as one `[[` command instead of splitting into a
  phantom command whose executable is the next test operand. Operand order no
  longer changes the result, and every unbounded or unbalanced span keeps the
  previous split-and-fail outcome. The shared segmenter is unchanged.
  Package-scanner rule version advances to `1.18.0`, invalidating cached results
  from earlier rule versions.
- Repository-provenance analysis now blanks `case` arm pattern lists before the
  shared segmenter sees the text. Arm patterns are string-match data, not
  commands, but each pattern used to become a phantom command (the `*)` wildcard
  arm even flipped repository completeness through the glob-ambiguity rule).
  The `)`/`;;`/`;&`/`;;&` boundaries, the `case` word and every arm body stay
  intact, so commands inside an arm are still analyzed and captured; unbounded
  or unbalanced `case` text keeps the previous outcome. Package-scanner rule
  version advances to `1.19.0`, invalidating cached results from earlier rule
  versions.
- Repository-provenance path collection now classifies `[`, `[[` and `test`
  commands instead of treating them as ordinary operands. The builtin name is
  never a repository operand (its `[` character used to trip the glob-ambiguity
  rule), and test arguments are classified operator-aware: operands of
  file-test primaries (`-f`, `-d`, `-ef`, …) are captured with the same
  cwd-joined ambiguity rules as transfer sources, while string/integer
  comparison operands are data. Unrecognized or unbounded test grammar withholds
  a complete result. Package-scanner rule version advances to `1.20.0`,
  invalidating cached results from earlier rule versions.
- Repository-provenance `case` arm masking now treats Bash's optional leading
  `(` group (`case $x in (a) …`) as part of the pattern list, so the `)` that
  closes it is the arm terminator instead of a subshell close. That shape used
  to blank the whole arm body and could drop an `install` command while still
  reporting a complete result; a pattern list that never reaches its `)` is
  malformed and now falls back to the unmasked text. Package-scanner rule
  version advances to `1.21.0`, invalidating cached results from earlier rule
  versions.
