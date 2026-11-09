# AuraScan 0.15.1 security gate evidence

Status: package-only release gate, 2026-11-09.

Scope: R1 (MCP descriptor containment), R2 (root `/` rejection), R6
(user `makepkg.conf` guard) and the F1/F2 residuals (code-loading keys and
literal value-side execution shapes). R8 (recovery-image validation when
`ukify` is absent) is explicitly deferred to a recovery-bearing release.

## Verdicts

- Independent Red review: no blocker. Three low-severity observations were
  resolved in the candidate: directory-swap diagnostic, whitespace-wrapped
  root, and guard-boundary wording. The same-inode content boundary is
  documented; inode reuse remains unproven.
- Independent Reviewer gate: `APPROVE` for the recorded package-only source
  slice. No blocking findings. R8 remains open and is not represented as
  fixed.
- Release disposition: package-only. The retained recovery image is
  `aurascan-recovery-0.10.11-x86_64.iso`, released 2026-10-21, SHA-256
  `df78c277c73349bab532c890789a476d0746a5a2b9dbab10307fd0c6c482841c`.
  ISO and UKI gates were not rerun for 0.15.1.

## Reproduction

- Focused MCP and makepkg tests: `285 passed`.
- Full suite: `5859 passed, 3 skipped`.
- `compileall`, both presenter-coverage audits, and `git diff --check`: exit 0.
- Observed skips: AntiCopy parity checkout absent or dirty; optional Qt binding
  not installed.
- Red and Reviewer each reproduced the symlink, rename, parent-directory and
  directory-swap refusals without receiving outside-root bytes. The Reviewer
  ran the real-bash source-gate oracle and a separate whitespace-root matrix.

## Limits

The `makepkg.conf` guard is a bounded defense-in-depth check, not a sandbox.
It does not inspect compiler, linker or compression configuration; `CFLAGS`,
`CC`, `CXX`, `RUSTFLAGS` and `COMPRESS*` remain trusted input. End-to-end
`makepkg` sourcing with a hostile configuration, the devtools sandbox handoff,
recovery ISO/UKI gates, Python 3.8, and non-Linux semantics were not executed
for this release.

Detailed exploitation notes remain in the private security research archive.
This public record is intentionally limited to scope, verdict, reproduction
counts and residual boundaries.
