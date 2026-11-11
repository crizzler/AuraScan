# R10 sandbox cleanup hardening — implementation evidence

Date: 2026-11-12
Baseline: AuraScan 0.17.0, HEAD `40f0e778dcbd66bfd623300542e1d33175a91899`
Scope: package-only; no recovery, packaging, version, or release change.

## Boundary

The privileged sandbox cleanup now reuses the build's captured `sudo` and `rm`
`TrustedTool` objects and revalidates both identities immediately before the
`sudo rm` command. Stored display paths are never executed, and cleanup never
recaptures a tool. Verified success requires both a usable exit status of zero
and an observed-absent tree. Missing objects, stale identities, validation
exceptions, timeouts, spawn failures, nonzero status, malformed completion
evidence, and a tree that remains after a nominally successful command all
produce a truthful warning. A failed build preserves the original
`SandboxBuildError` text and the wrapper's `EXIT_SANDBOX_FAILED` while adding
the cleanup warning.

## Candidate

| File | SHA-256 |
| --- | --- |
| `aurascan/core/build_sandbox.py` | `b4db43e6455bc8073345fd66623090ad1c82907868118d66702ffaa399ae2baa` |
| `aurascan/makepkg_wrapper.py` | `c531645493a7aafeb334f60f70fc48d04d1d3c91fb7909d7ca9ed80540dbd81e` |
| `tests/test_build_sandbox.py` | `a777f6f544e518a8ab4d214e71903bda258d0fb39bc5fea88cb8aba7d41fd7b2` |
| `tests/test_makepkg_wrapper.py` | `848bf8d1947572d5f403c72b91605ffb43d0427cec538668979f8e7c0d1f33a6` |

## Verification

- Focused tests, Python 3.14 and Python 3.8:
  `322 passed` on both interpreters.
- Source gates: `compileall`, presenter `--strict`, presenter
  `--strict-medium`, and `git diff --check` all exited 0.
- Full source suite:
  `5934 passed, 5 skipped, 1 failed`. The sole failure is
  `tests/test_injection_golden.py::test_golden_head_matches_the_live_anticopy_head`,
  which compares a fixed golden AntiCopy head with the live external checkout.
  It is outside this diff and the full suite is **not green**.
- Red security disposition `t_c1f5846b`: **NO BLOCKER** for the narrow
  captured-tool-identity cleanup boundary. Independent rootless probe 30/30.
- Reviewer `t_31b974dc` and `t_9e281882`: no new scoped code blocker; both
  returned `CHANGES REQUESTED` solely for evidence-payload shape. A fresh Red
  correction `t_16545599` supplied structured metadata and preserved the same
  candidate hashes. The further evidence-only normalization card `t_dd5083f8`
  was stopped and archived because it was not adding security evidence. This
  is not a Reviewer APPROVE and must not be reported as one.

## Not verified

- Real policy, TTY, and timestamp behavior of the installed `sudo`; no
  privileged cleanup was run.
- Actual root-owned tree permissions, mounted-filesystem behavior, and
  privileged descendant termination.
- Revalidate-to-execute TOCTOU (Red F1).
- Cleanup warning attachment for non-`SandboxBuildError` failed-build
  exceptions (Red F2); preserved as a non-blocking observation.
- Target-path/ancestor race resistance and same-UID/root interference.

R3, R4, R7, and R9 remain untouched and unclosed. This slice does not change
Daybreak eligibility and is not a release.
