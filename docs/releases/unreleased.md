# AuraScan Unreleased

Changes after v0.9.1 will be recorded here.

## AUR maintainer-worm static detection

- `SUPPLYCHAIN-AUR-REPO-PROPAGATION-001` is a CRITICAL hard blocker for the
  generic behavior used by the August 2026 `xsnow`/`xsnow-bin` incident: a
  canonical AUR Git target correlated with repository mutation or staging and
  a non-dry-run push bound to that AUR endpoint or configured remote in
  deterministic PKGBUILD or declared install-hook control text.
- The rule does not fire for an AUR URL, clone/fetch behavior, a push explicitly
  bound to another host, a dot-prefixed filename, comments, quoted
  documentation, or any one behavior family alone. It is intentionally not a
  blanket deep-static source rule for legitimate upstream release tooling.
- `INSTALL-HOOK-UNINSPECTED-001` is a HIGH hard blocker when a literal local
  `install=` target, including a dot-prefixed hook, is absent, unreadable,
  unsafe, ambiguous, or any component of its declared relative path under the
  package directory is a symlink. Failure-state blocker reports may be cached,
  but no unresolved hook can reuse or create an allow decision or review
  acceptance.
- Findings describe suspicious static intent and a potential static
  propagation chain. They do not claim that package code ran, a remote push
  succeeded, maintainer credentials were usable, or a machine/account was
  compromised.
- For AuraScan v0.9.2, the package-scanner rule version advances from `1.2.0`
  to `1.3.0`, invalidating older cached package decisions while the Instruction
  Guard report schema and rule version remain `1.0`.

## Agent Instruction Guard review explanations

- Terminal review now distinguishes integrity-only first-seen/change review
  from suspicious-content findings and prioritizes suspicious files.
- Content findings report deterministic one-based line ranges, semantic
  behavior labels, and fixed reasons without printing source snippets. An
  incomplete bounded scan is labeled as the current page with continuation
  still pending.
- Separately enabled AI receives only bounded opaque evidence IDs, fixed
  reasons, behavior labels, and deterministic locations. Its advisory
  rationales map to that evidence and cannot invent lines, establish trust, or
  claim execution or compromise. Clean first-seen files remain AI
  `not-needed`.
