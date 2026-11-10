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
