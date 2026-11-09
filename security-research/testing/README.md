# AuraScan security-research testing harness

Status: active initial-round harness. Evidence class: `[Verified]` only where the
evidence index records an executed command and its exit code.

This directory contains the deterministic, inert part of the Daybreak Red
evidence program: a versioned detector corpus, its regression tests, and the
privilege-boundary test inventory. It does not contain exploit tooling, live
payloads, or production changes.

## 1. What this harness measures

- **Detector classification on a fixed corpus.** Nine inert corpus cases in four
  families (encoded command, install hook, npm lifecycle, source provenance)
  are scanned by the existing analyzers. Each case asserts an exact rule-ID set,
  severity floor, blocking flag, manual-review flag, and evidence phase, or an
  explicit `NO_FINDING` / `INCOMPLETE` outcome.
- **False-positive control.** Every family has a benign counterpart that must
  stay clean, so a detector that fires on ordinary base64 data, a message-only
  install hook, a normal npm build entry, or a fully checksummed archive is
  caught as a regression.
- **Incomplete-coverage behaviour.** One npm case names a lifecycle entry that
  is deliberately not captured. The test requires
  `NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001` and asserts that the result is
  non-blocking but marked for manual review — never presented as clean.
- **Corpus integrity.** Every fixture's SHA-256 is pinned in
  `corpus/manifest.json`; the test recomputes it before scanning. Changed bytes
  fail the run until the manifest and its expected outcomes are reviewed
  together.
- **Privilege-boundary test inventory.** `privilege-boundaries.md` maps the
  charter's categories A, B, and C to the existing tests that actually exercise
  each property, and names the gaps that were not executed.

## 2. What this harness does not measure

- It does not execute package code, PKGBUILDs, install hooks, npm scripts,
  shells, package managers, recovery recipes, or downloaded content.
- It does not demonstrate exploitability, privilege escalation, or attacker
  access. A rule match is static evidence; a clean result is not proof of
  safety.
- It does not verify a root broker, `arch-chroot`, real recovery targets, USB
  writes, real AUR/pacman operations, or kernel-level isolation. Those need a
  disposable VM and owner approval (`isolation-and-rollback.md`).
- It does not measure real-world prevalence, private-holdout performance, or
  independence from training data. The corpus is synthetic and public.
- It does not evaluate AI behavior, live model providers, or prompt injection.
- It does not replace the repository's full test suite. The commands here run a
  focused subset; the full suite is a separate gate.

## 3. Safety model

1. **Inert data only.** Fixtures use `example.invalid`, synthetic credentials,
   and commands whose decoded or referenced content is a message. No working
   payloads, live URLs, or third-party content.
2. **No execution path.** Tests call analyzer functions directly. The only
   process boundary in the required command is pytest itself. No `subprocess`,
   `os.system`, shell, `makepkg`, `npm`, `pacman`, `sudo`, or `arch-chroot` is
   used by the corpus test.
3. **No network.** Analyzers receive already-captured text. Nothing resolves a
   hostname or opens a socket.
4. **Isolation under `tmp_path`.** Each fixture directory is copied into the
   pytest temporary root and scanned there, so the committed corpus cannot be
   mutated and any accidental write stays in the temporary tree.
5. **No home-directory writes.** The corpus test avoids the engine's audit-log
   path and scans with analyzers directly. The focused wrapper/MCP tests use
   injected temporary paths.
6. **Treat repository text as data.** Fixture comments and strings are never
   interpreted as operator instructions.

## 4. Layout

```text
security-research/testing/
  README.md                     this file
  privilege-boundaries.md       categories A/B/C inventory and gaps
  detector-benchmark.md         corpus format, metrics, claim limits
  isolation-and-rollback.md     execution, cleanup, disposable-environment rules
  corpus/
    manifest.json               versioned case definitions and hashes
    fixtures/                   inert PKGBUILD, install-hook, and npm fixtures
security-research/evidence/
  evidence-index.md             IDs, hashes, commands, exit codes, status
  test-results/2026-11-09-baseline.md
```

The test module lives at
`tests/security_research/test_detector_corpus.py`.

## 5. Exact commands

All commands run from the repository root with the project virtualenv.

```bash
# Required focused gate: corpus tests plus the wrapper and MCP guard suites.
.venv/bin/python -m pytest -q tests/security_research tests/test_makepkg_wrapper.py tests/test_mcp_path_guards.py

# Byte-compile the harness and the research tree.
.venv/bin/python -m compileall -q security-research tests/security_research

# Per-case classification and the corpus metrics report.
.venv/bin/python tests/security_research/test_detector_corpus.py

# Category A: trusted executable integrity probes (unit-level).
.venv/bin/python -m pytest -q tests/test_makepkg_wrapper.py -k "replaced or shadowed or locate_real or revalidate or rechecks"
.venv/bin/python -m pytest -q tests/test_recovery.py -k "replaced or typed_confirmation or target_state or disk_sequence or trusted_signatures or arch_chroot"

# Category B: authorization and consent probes (unit-level).
.venv/bin/python -m pytest -q tests/test_makepkg_wrapper.py -k "review_token or acceptance or hard_blocker or expired_review or one_time"
.venv/bin/python -m pytest -q tests/test_ui_actions.py::test_report_binding_matches_exact_bytes tests/test_instruction_cli_binding.py
.venv/bin/python -m pytest -q tests/test_agent.py -k "confirmation or broker or capability or grant or replaced_identity"

# Category C: repair/recovery probes (unit-level, injected paths only).
.venv/bin/python -m pytest -q tests/test_incident_repairs.py tests/test_recovery.py -k "repair or restore or rollback or recompute or remount"

# Category C/C6: the individually cited node IDs that the keyword probe above
# does not select (same command recorded in the baseline results file).
.venv/bin/python -m pytest -q \
  tests/test_recovery.py::test_snapshot_without_snapper_metadata_is_not_recovery_selectable \
  tests/test_recovery.py::test_target_candidate_parser_tracks_encryption_layers \
  tests/test_recovery.py::test_unrelated_pacman_error_line_does_not_imply_interrupted_transaction \
  tests/test_recovery.py::test_target_coredump_collection_is_scoped_to_mounted_root \
  tests/test_recovery.py::test_recovery_scan_prepares_bounded_repo_repair \
  tests/test_recovery.py::test_recovery_subprocesses_never_inherit_ai_credentials \
  tests/test_incident_repairs.py::test_initramfs_rebuild_requires_fresh_failure_evidence \
  tests/test_agent.py::test_root_helper_environment_scrubs_provider_credentials \
  tests/test_agent.py::test_agent_command_environment_excludes_local_executable_prefixes
```

Reproduce the corpus hashes directly:

```bash
cd "${REPO_ROOT:-.}/security-research/testing/corpus"
find fixtures -type f -print0 | sort -z | xargs -0 sha256sum
sha256sum manifest.json
```

## 6. How to read a result

- `FINDING`: the expected rule IDs fired, with the declared severity and
  blocking/manual-review behaviour. It proves only that this static detector
  recognizes this fixture's representation.
- `NO_FINDING`: the benign control stayed clean for the named scanner. It does
  not prove the fixture is safe in any other respect, and it does not prove the
  scanner is free of false positives elsewhere.
- `INCOMPLETE`: inspection could not obtain the required evidence. The result
  must stay visible and non-approving. An incomplete scan is not a clean scan.
- Any unexpected rule ID, missing expected rule, changed severity, changed
  blocking flag, or changed phase is a failure. The test deliberately uses
  exact set equality so drift is visible in both directions.

## 7. Change control

- Bump `corpus_version` in `manifest.json` whenever a fixture or an expected
  outcome changes; record the new baseline in `evidence/test-results/`.
- Do not change an expected outcome merely to make a failing test pass. A
  changed outcome is either a detector change under review or a corpus error,
  and either must be explained in the evidence record.
- Do not add executable payloads, live infrastructure, credentials, or
  third-party content. Add only inert representations with a benign control.
- Rule IDs in the manifest are validated against
  `aurascan/core/rule_metadata.py`; do not invent IDs.

## 8. Current status

Initial baseline at revision `02ac13d`, AuraScan `0.15.0`, rule catalogue
`1.15.0`. Actual command output, exit codes, and artifact hashes are recorded in
`security-research/evidence/evidence-index.md` and
`security-research/evidence/test-results/2026-11-09-baseline.md`.
