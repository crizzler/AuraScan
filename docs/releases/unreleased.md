# AuraScan Unreleased

Changes after v0.10.19:

- Add `aurascan ui`, a read-only `aurascan-ui/1` evidence snapshot for desktop
  user interfaces, with contract tests that fail closed on malformed, unknown,
  or unbounded evidence.
- Add `aurascan ui --report FILE`, a bounded projection of a saved AuraScan
  JSON report for the desktop renderer. It drops raw package bytes, absolute
  paths, finding identifiers and hashes, and rejects unknown vocabularies.
- Add `aurascan ui --actions`, the fixed desktop action catalog with validated
  argument substitution and a hash-binding helper for future renderer-
  requestable mutations; state-changing actions remain terminal-only.
- Add the hardened Electron shell for the desktop console: two fixed read-only
  operations, allowlisted child environment, bounded output, and a headless
  self-test. It is not packaged yet.
- Add the phase 2 desktop evidence console prototype under `desktop/` and the
  design and boundary notes in `docs/DESKTOP_UI_DESIGN.md`. The prototype is
  not packaged, has no action surface, and is not part of any release artifact.
