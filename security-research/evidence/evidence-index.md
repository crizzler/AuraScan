# Evidence index — Daybreak initial round

Status: initial-round index. All executed evidence below was produced in this
round. `[Verified]` means the command was run and the listed artifact exists
with the recorded hash; it does not mean the underlying security claim is
proven beyond the tested configuration.

## Identity

| Field | Value |
|---|---|
| Program | AuraScan Daybreak Red evidence program, initial round |
| Baseline revision | `02ac13d6e56c0eccfd2aa318a6693bb4fa80f0a0` (`02ac13d`) |
| AuraScan version | `0.15.0` |
| Rule catalogue version | `1.15.0` |
| Corpus version | `1.0.0` |
| Recorded at | `2026-11-09T16:17:59+08:00` |
| Python (venv) | `3.14.8` |
| Platform | `Linux 7.3.0-4-cachyos x86_64` |
| Working tree | Uncommitted; this round made no commits or pushes |

This index covers `security-research/testing/`, `security-research/evidence/`,
and `tests/security_research/`. It does not cover other owners' files.

## Executed evidence

| ID | Claim | Command | Result | Status |
|---|---|---|---|---|
| `DB-EV-001` | Corpus tests, wrapper tests, and MCP guard tests pass together. | `.venv/bin/python -m pytest -q tests/security_research tests/test_makepkg_wrapper.py tests/test_mcp_path_guards.py` | `166 passed in 6.55s`, exit `0` | `[Verified]` |
| `DB-EV-002` | Harness and research tree byte-compile. | `.venv/bin/python -m compileall -q security-research tests/security_research` | no output, exit `0` | `[Verified]` |
| `DB-EV-003` | Corpus classifies 9 cases and computes metrics from the same run. | `.venv/bin/python tests/security_research/test_detector_corpus.py` | 9 case rows; `detection_rate=4/4`; `false_negative_rate=0/4`; four `0/1` false-positive rows; exit `0` | `[Verified]` |
| `DB-EV-004` | Category A wrapper probes pass (unit-level). | `.venv/bin/python -m pytest -q tests/test_makepkg_wrapper.py -k "replaced or shadowed or locate_real or revalidate or rechecks"` | `7 passed, 135 deselected`, exit `0` | `[Verified]` |
| `DB-EV-005` | Category A recovery-tool probes pass (unit-level). | `.venv/bin/python -m pytest -q tests/test_recovery.py -k "replaced or typed_confirmation or target_state or disk_sequence or trusted_signatures or arch_chroot"` | `10 passed, 59 deselected`, exit `0` | `[Verified]` |
| `DB-EV-006` | Category B review-token and expiry probes pass. | `.venv/bin/python -m pytest -q tests/test_makepkg_wrapper.py -k "review_token or acceptance or hard_blocker or expired_review or one_time"` | `15 passed, 127 deselected`, exit `0` | `[Verified]` |
| `DB-EV-007` | Category B report-byte binding and CLI binding probes pass. | `.venv/bin/python -m pytest -q tests/test_ui_actions.py::test_report_binding_matches_exact_bytes tests/test_instruction_cli_binding.py` | `9 passed`, exit `0` | `[Verified]` |
| `DB-EV-008` | Category B root-broker, exact-grant, and identity probes pass (simulated root). | `.venv/bin/python -m pytest -q tests/test_agent.py -k "confirmation or broker or capability or grant or replaced_identity"` | `7 passed, 168 deselected`, exit `0` | `[Verified]` |
| `DB-EV-009` | Category B command-policy and access-ceiling probes pass. | `.venv/bin/python -m pytest -q tests/test_agent.py -k "command_policy or escalation or access_ceiling or followup_agent_command or command_approval or decline"` | `129 passed, 46 deselected`, exit `0` (11 distinct parametrized tests) | `[Verified]` |
| `DB-EV-010` | Category C repair, rollback, and remount probes pass (injected paths). | `.venv/bin/python -m pytest -q tests/test_incident_repairs.py tests/test_recovery.py -k "repair or restore or rollback or recompute or remount"` | `25 passed, 61 deselected`, exit `0` | `[Verified]` |
| `DB-EV-011` | New Markdown/JSON/Python files have no trailing whitespace or CRLF bytes. | `grep -rIn "[[:blank:]]$" security-research tests/security_research --include="*.md" --include="*.json" --include="*.py" --include="*.install" --include="PKGBUILD"` and `grep -rIlU $'\r' ...` | both reported clean; exit `0` from the wrapper `if` | `[Verified]` |
| `DB-EV-012` | Fixture URLs use only `example.invalid`; no live-danger command strings are present. | `grep -rn "http" security-research/testing/corpus/fixtures` plus a repository content search for `aur\.archlinux|/dev/tcp|mkfs\.|nc -e|bash -i|sh -i|curl |wget ` over the same directory | 13 URL lines, all `https://example.invalid/...`; 0 live-danger matches | `[Verified]` |
| `DB-EV-013` | Baseline revision and declared versions. | `git rev-parse HEAD`; `grep -n '^version' pyproject.toml`; `grep -n 'rule_version' aurascan/core/engine.py` | `02ac13d...`; `0.15.0`; `1.15.0` | `[Verified]` |
| `DB-EV-014` | Category C/C6 node IDs cited in the matrix pass (recovery metadata, target selection, failure evidence, environment scrubbing). | `tests/test_recovery.py::test_snapshot_without_snapper_metadata_is_not_recovery_selectable`, `::test_target_candidate_parser_tracks_encryption_layers`, `::test_unrelated_pacman_error_line_does_not_imply_interrupted_transaction`, `::test_target_coredump_collection_is_scoped_to_mounted_root`, `::test_recovery_scan_prepares_bounded_repo_repair`, `::test_recovery_subprocesses_never_inherit_ai_credentials`, `tests/test_incident_repairs.py::test_initramfs_rebuild_requires_fresh_failure_evidence`, `tests/test_agent.py::test_root_helper_environment_scrubs_provider_credentials`, `::test_agent_command_environment_excludes_local_executable_prefixes` (full command in the baseline results file) | `9 passed in 0.21s`, exit `0` | `[Verified]` |

## Artifact hashes

Hashes were computed after the final edit of each file. If any file changes,
its row is stale and must be recomputed. The evidence index itself is not
self-hashed.

### Documents and test module

| Artifact | Path | SHA-256 |
|---|---|---|
| Harness README | `security-research/testing/README.md` | `faf93e65d3005c41912159139a320ba44b8594b818b5d1c61309a6953f15615f` |
| Privilege-boundary matrix | `security-research/testing/privilege-boundaries.md` | `5d8fea1d5197623464eed241941d0551430455d84f7826f7ef2cb0c8be5c6cd9` |
| Detector benchmark | `security-research/testing/detector-benchmark.md` | `782f0000e6f4bc32a1d7b4ac2840f6c20fb428843717b0fdc30a4e5436c5b220` |
| Isolation and rollback | `security-research/testing/isolation-and-rollback.md` | `a820d74f25f1152a8d27aeee90d946d9975cef54decb75ab5448595151838ee9` |
| Baseline results | `security-research/evidence/test-results/2026-11-09-baseline.md` | `cf1202caa130f97aa8dea38067e79aac161108ca446d4d6eefbaaf02cdea892e` |
| Corpus manifest | `security-research/testing/corpus/manifest.json` | `1f874db65118953a0f52fa4cc4ed72ae8d03a19da74d06b1c74a58cc76d33508` |
| Corpus test module | `tests/security_research/test_detector_corpus.py` | `06027c7cd52cb01c7b2eabe9490f7d91106aa92a86f9165297ad578142898f55` |

### Corpus fixtures (13 files)

| Fixture | Path (relative to `security-research/testing/corpus/`) | SHA-256 |
|---|---|---|
| Encoded command, adversarial | `fixtures/pkgbuild-base64-exec/PKGBUILD` | `3b0c5fa5d1381910b43ed0daa0a27d6c42a820629c08a82f13b5f00f8c69a158` |
| Encoded command, benign | `fixtures/pkgbuild-base64-benign/PKGBUILD` | `871f15f757b1ed0c93326533647966bb10b666a7a213a492999872a15919d1e3` |
| Install hook, adversarial | `fixtures/install-hook-privileged/PKGBUILD` | `f3097ceccbe55e87d6688382cbccc9aae7d602c6017654c5dc4d24a427997a51` |
| Install hook, adversarial | `fixtures/install-hook-privileged/corpus-install-hook-privileged.install` | `3219ddb7a99e290ec6169ca5d0472987240c7100206f8a7b2a907bed7fc8ed14` |
| Install hook, benign | `fixtures/install-hook-benign/PKGBUILD` | `5079c4dfa948a215c978151a95308fbb3030095dddf9b7e33adbaa4e2a78bd9a` |
| Install hook, benign | `fixtures/install-hook-benign/corpus-install-hook-benign.install` | `4044f797d19829a769bb6b92b86c0f70f3faa0f99a211efb570325be45038049` |
| npm lifecycle, adversarial | `fixtures/npm-lifecycle-env-exfil/package.json` | `035c4373fa2ea67b2f483e84b3d7248c9cfd2d001bb7f5ee996d00f6563f9740` |
| npm lifecycle, adversarial | `fixtures/npm-lifecycle-env-exfil/setup.js` | `2428d29931556361b7a30358ddea0573f78bda6e2c27e962d1ddbd397238794c` |
| npm lifecycle, benign | `fixtures/npm-lifecycle-benign/package.json` | `3b8ebd37406f8f3c65c6cb8eaffc1050f5d5d2e8af0f8d560bb9e183625693bf` |
| npm lifecycle, benign | `fixtures/npm-lifecycle-benign/build.js` | `3fba731e16d592c4717213f9e72baec86c2574aef2800f9d95f5cb541b197f48` |
| npm lifecycle, coverage | `fixtures/npm-lifecycle-incomplete/package.json` | `e38bd1bc7021c6bd28fdc7327c73867a9614fb1f0dd0a115f4f55ce744976ef7` |
| Source provenance, adversarial | `fixtures/pkgbuild-source-git-ambiguous/PKGBUILD` | `ec484617c7640cb5c8089d76ddda85cf9e020c6d1bee7a2232dfbcc33f8aad4e` |
| Source provenance, benign | `fixtures/pkgbuild-source-pinned-archive/PKGBUILD` | `1a39e7f3461ae8969cc197c2c0e577c1e2ab5063cf4c19ba53146ee60f980f36` |

These 13 hashes match the `files[].sha256` entries in
`manifest.json`. The test recomputes the hashes for every case before scanning
it and fails on any mismatch (`DB-EV-001`, `DB-EV-003`).

## Reproduce the hashes

```bash
cd security-research/testing/corpus
sha256sum manifest.json
find fixtures -type f -print0 | sort -z | xargs -0 sha256sum

cd -
sha256sum \
  security-research/testing/README.md \
  security-research/testing/privilege-boundaries.md \
  security-research/testing/detector-benchmark.md \
  security-research/testing/isolation-and-rollback.md \
  security-research/evidence/test-results/2026-11-09-baseline.md \
  tests/security_research/test_detector_corpus.py
```

## Explicitly not executed

| Item | Status | Reason |
|---|---|---|
| Symlink or rename replacement at a real trusted executable path | `NOT EXECUTED` | Host-mutating; needs a disposable VM and owner approval. |
| Concurrent TOCTOU race against `makepkg`, root broker, or recovery tools | `NOT EXECUTED` | Requires a coordinated adversary process in a disposable environment. |
| Real second-process stolen-capability replay | `NOT EXECUTED` | Single-process unit tests cannot prove cross-process isolation. |
| Compromised recovery target filesystem | `NOT EXECUTED` | Needs a simulated/disposable target and owner approval. |
| Real USB identification/write, recovery boot, or `arch-chroot` execution | `OUT OF SCOPE` | Privileged/destructive; excluded by the card. |
| Real AUR build or package installation | `OUT OF SCOPE` | Excluded by the card and repository safety invariants. |
| Network acquisition, registry query, live AI/provider call | `OUT OF SCOPE` | Corpus is offline and inert; no network was used. |
| Private-holdout or real-world prevalence measurement | `OUT OF SCOPE` | Corpus is synthetic and public; any such claim would be invalid. |
| Full repository test suite | `NOT EXECUTED` | This round ran the card's focused gate, not the release gate. |
| `tests/security_research/test_review_binding.py` | `NOT CREATED` | Existing tests already cover changed-report-byte binding: `tests/test_ui_actions.py::test_report_binding_matches_exact_bytes` (`DB-EV-007`) and `tests/test_makepkg_wrapper.py::test_review_token_invalid_if_pkgbuild_hash_changes` / `::test_review_token_invalid_if_finding_set_changes` (`DB-EV-006`). |

## Evidence limitations

- A passing test establishes only the tested configuration at revision
  `02ac13d`; it does not prove AuraScan is secure.
- The corpus is synthetic and public, so no private-holdout or prevalence
  inference is valid.
- The privilege-boundary evidence is unit-level with injected temp paths and a
  simulated root UID. It is not exploit validation.
- No artifact here was produced by executing package code, a hook, an npm
  script, a shell, a package manager, or downloaded content.
