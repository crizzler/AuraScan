# Privilege-boundary validation matrix

Status: initial-round inventory and gap register. Baseline revision `02ac13d`,
AuraScan `0.15.0`, rule catalogue `1.15.0`.

This matrix covers the charter's Phase Two categories A (trusted executable
integrity), B (authorization and consent), and C (repair and recovery). It
separates three different things that are easy to confuse:

- a test that exists,
- a test that was actually executed in this round, and
- a test that proves the property named in the row.

Every `EXECUTED` row below was run in this round; the command, pass count, and
exit code are in `security-research/evidence/evidence-index.md`. No row claims
host-level or disposable-VM execution. Existing tests use injected temporary
paths and simulated privileged entry points; they do not run `sudo`,
`makepkg`, `pacman`, `arch-chroot`, a real recovery target, or a real USB
device.

## Status legend

| Status | Meaning |
|---|---|
| `EXECUTED` | A named existing test (or the new corpus test, where stated) was run in this round and passed. |
| `NOT EXECUTED` | The property has no safe probe in this round. The gap is real; it is not marked covered. |
| `OUT OF SCOPE` | The property requires host privileges, a disposable VM/container, a real recovery target, or external infrastructure, and is excluded by the card's hard constraints. |

## Category A — trusted executable integrity

| ID | Property | Existing test(s) | What the test actually proves | Gap | New safe probe this round | Status |
|---|---|---|---|---|---|---|
| A1 | PATH manipulation / shadowed `makepkg` | `tests/test_makepkg_wrapper.py::test_wrapper_refuses_path_shadowed_makepkg_before_invocation`, `::test_locate_real_makepkg_prefers_canonical_path_over_sbin` | An injected locator that resolves to a temporary shadow executable is refused before the handoff; the configured canonical path wins when a shadow directory precedes it in PATH. | Uses an injected locator, not a real mutated `PATH` environment. | None added | `EXECUTED` |
| A2 | Executable substitution before invocation | `::test_wrapper_refuses_replaced_makepkg_before_invocation` | A failed trusted-tool revalidation stops the run before any `makepkg` call and does not leak the internal replacement detail. | Simulated revalidation failure; does not replace bytes on disk between capture and exec. | None added | `EXECUTED` |
| A3 | Identity change between validation and use | `::test_wrapper_rechecks_input_after_makepkg_tool_revalidation`, `::test_wrapper_revalidates_input_immediately_before_makepkg` | The PKGBUILD/input identity is recaptured after tool revalidation; a mutation blocks the handoff. | Covers the scanned input, not the executable's inode/content after the last revalidation. | None added | `EXECUTED` |
| A4 | Symlink replacement of the trusted executable | None for `/usr/bin/makepkg` or recovery tools. `tests/test_mcp_path_guards.py::test_21_symlink_escaping_the_root_is_refused` covers symlink containment for MCP reads only. | The MCP test proves a read refuses a symlink that escapes its root; it says nothing about executable identity. | No test creates a symlink at the trusted executable path or swaps a validated path for a symlinked one. | None added | `NOT EXECUTED` |
| A5 | Stale executable fingerprint | `::test_wrapper_refuses_replaced_makepkg_before_invocation`, `tests/test_agent.py::test_root_helper_refuses_replaced_identity_before_next_request` | Revalidation is required again before the next privileged request; a changed identity is refused. | Inode reuse/content replacement between the last revalidation and the kernel exec is not simulated. | None added | `EXECUTED` for revalidation policy; `NOT EXECUTED` for the real race window |
| A6 | Recovery tool replacement | `tests/test_recovery.py::test_snapshot_restore_refuses_replaced_snapper_binary`, `::test_initramfs_rebuild_refuses_replaced_generator_binary`, `::test_dkms_autoinstall_refuses_replaced_dkms_binary`, `::test_pacman_action_refuses_replaced_package_manager`, `::test_arch_chroot_tool_validation_fails_closed` | Each recovery path rejects a tool whose identity no longer matches the trusted capture, and `arch-chroot` validation fails closed. | Uses fixture paths and injected tool identity; no real `/usr/bin` mutation, no booted recovery environment. | None added | `EXECUTED` |
| A7 | Concurrent race involving a trusted reference | None. All revalidation tests are sequential. | A sequential mutation is detected; a simultaneous swap is not exercised. | Requires an adversary process racing the exact window. | None added | `NOT EXECUTED` |
| A8 | Real host or disposable-VM substitution test | — | — | Would modify or race host system paths or a VM image. | — | `OUT OF SCOPE` |

## Category B — authorization and consent

| ID | Property | Existing test(s) | What the test actually proves | Gap | New safe probe this round | Status |
|---|---|---|---|---|---|---|
| B1 | Replayed one-time authorization | `tests/test_makepkg_wrapper.py::test_one_time_acceptance_cannot_be_reused` | A one-time review acceptance cannot authorize a second handoff. | SQLite store is local to a temporary path; no cross-machine replay. | None added | `EXECUTED` |
| B2 | Stale / expired approval | `::test_expired_review_decision_cannot_be_used`, `tests/test_agent.py::test_root_broker_refuses_wrong_capability_and_expired_session` | An expired review decision and an expired root session are both refused. | Clock is injected; no real elapsed-time test. | None added | `EXECUTED` |
| B3 | Cross-process / cross-context authorization | `tests/test_agent.py::test_root_broker_binds_capability_process_tty_and_plan`, `::test_root_broker_refuses_wrong_capability_and_expired_session`, `::test_root_session_requires_exact_grant_and_snapshot_waiver` | Session issuance binds UID, origin PID/start time, TTY, and context fingerprint; a wrong capability or expired session is refused. | Runs in one pytest process with a simulated `geteuid() == 0`; does not start a second unprivileged process attempting a stolen capability. | None added | `EXECUTED` for binding policy; `NOT EXECUTED` for a real second-process attempt |
| B4 | Mismatched action identifiers / malformed binding | `tests/test_instruction_cli_binding.py::test_binding_without_an_action_is_refused`, `::test_a_malformed_expected_hash_is_refused` | A binding without an action and a malformed expected hash are refused before forwarding. | UI and CLI paths only; does not exhaust every caller. | None added | `EXECUTED` |
| B5 | Changed report contents after approval | `tests/test_ui_actions.py::test_report_binding_matches_exact_bytes`, `tests/test_makepkg_wrapper.py::test_review_token_invalid_if_pkgbuild_hash_changes`, `::test_review_token_invalid_if_finding_set_changes` | Changed report bytes fail `verify_report_binding`; changed PKGBUILD bytes or finding set invalidate the review token. | Covered for the tested callers; no GUI-process-level re-read race. | None added — existing coverage is sufficient, so `tests/security_research/test_review_binding.py` was deliberately not created | `EXECUTED` |
| B6 | Authorization request outside the capability set | `tests/test_agent.py::test_agent_command_policy_rejects_remote_dynamic_and_build_commands`, `::test_agent_command_policy_rejects_sensitive_cwd_and_symlink_targets`, `::test_run_agent_enforces_configured_access_ceiling_and_tty`, `::test_followup_agent_command_cannot_exceed_configured_access`, `::test_agent_escalation_owns_the_access_policy_and_refusals` | Command policy rejects remote, dynamic, build, sensitive-cwd, and symlink-target commands; a follow-up cannot exceed the configured access ceiling. | Policy is evaluated with fixture command strings; no real privileged execution is attempted. | None added | `EXECUTED` |
| B7 | Fresh consent for each exact command | `tests/test_agent.py::test_later_model_command_requires_a_new_confirmation_under_legacy_plan_mode`, `::test_user_shell_session_runs_only_after_command_approval_and_audits_privately`, `::test_user_shell_decline_runs_no_command_or_second_provider_request`, `::test_agent_response_rejects_commands_without_shell_grant_and_validates_shell_fields` | A later or changed model command requires a new confirmation; declining runs nothing; shell fields require an explicit grant. | Interactive consent is simulated; no real terminal session with a human. | None added | `EXECUTED` |
| B8 | Real cross-process stolen-capability attempt | — | — | Needs a second process and a broker boundary that only a disposable environment should exercise. | — | `OUT OF SCOPE` |

## Category C — repair and recovery

| ID | Property | Existing test(s) | What the test actually proves | Gap | New safe probe this round | Status |
|---|---|---|---|---|---|---|
| C1 | Malformed recovery metadata | `tests/test_recovery.py::test_snapshot_without_snapper_metadata_is_not_recovery_selectable`, `::test_target_candidate_parser_tracks_encryption_layers`, `::test_unrelated_pacman_error_line_does_not_imply_interrupted_transaction` | Unproven snapshot metadata is not selectable; ambiguous parser input does not create an interrupted-transaction claim. | Parser-level only; no malformed on-disk recovery image. | None added | `EXECUTED` |
| C2 | Manipulated repair evidence | `::test_snapshot_restore_validates_a_new_pre_recovery_snapshot_before_rollback`, `::test_snapshot_restore_refuses_rollback_when_new_snapshot_cannot_be_proven`, `::test_failed_initramfs_rebuild_restores_previous_image_set`, `tests/test_incident_repairs.py::test_initramfs_rebuild_requires_fresh_failure_evidence` | Rollback requires a provable new pre-recovery snapshot; a failed rebuild restores the previous image set; stale failure evidence is refused. | Evidence is synthetic and local; no tampered host evidence store. | None added | `EXECUTED` |
| C3 | Incorrect target selection | `::test_recovery_report_refuses_target_state_symlink_and_falls_back_to_runtime`, `::test_target_coredump_collection_is_scoped_to_mounted_root`, `::test_recovery_usb_cli_refuses_same_path_when_disk_sequence_changes` | A symlinked target-state path falls back to the private runtime; coredump collection stays under the mounted root; a changed disk sequence refuses same-path USB reuse. | No real block device, USB write, or booted target. | None added | `EXECUTED` for selection policy; `NOT EXECUTED` for a real device |
| C4 | Compromised simulated target filesystem | `tests/test_recovery.py::test_recovery_scan_prepares_bounded_repo_repair` (fixture `tmp_path` only) and the recovery scan fixtures | The scanner prepares only a bounded repository repair from a normal simulated target state. | A compromised target with hostile files, ACLs, or a mounted adversarial filesystem was not built; the cited test does not model one. | None added | `NOT EXECUTED` |
| C5 | Unsafe path traversal / symlink handling | `::test_recovery_report_refuses_target_state_symlink_and_falls_back_to_runtime`, `tests/test_mcp_path_guards.py::test_19_parent_traversal_is_refused`, `::test_20_absolute_path_outside_the_root_is_refused`, `::test_21_symlink_escaping_the_root_is_refused`, `::test_22_symlink_staying_inside_the_root_is_followed` | Traversal, absolute paths, and escaping symlinks are refused in the MCP read boundary; the recovery report does not follow a target-state symlink. | MCP and recovery are separate boundaries; this does not prove a shared sanitizer or cover every recovery path. | None added | `EXECUTED` for the cited boundaries; no shared-boundary claim |
| C6 | Unexpected privilege inheritance | `tests/test_recovery.py::test_recovery_subprocesses_never_inherit_ai_credentials`, `tests/test_agent.py::test_root_helper_environment_scrubs_provider_credentials`, `::test_agent_command_environment_excludes_local_executable_prefixes` | Child environments are scrubbed of provider credentials and local executable prefixes. | Environment inheritance only; kernel capabilities, supplementary groups, and `no_new_privs` are not tested. | None added | `EXECUTED` for environment; `NOT EXECUTED` for kernel privilege inheritance |
| C7 | Real recovery execution | — | — | Requires a disposable VM, a simulated target disk, and owner approval. | — | `OUT OF SCOPE` |

## Executed probe log

The commands below were run from the repository root. Counts are the actual
pytest result lines, not estimates.

| Probe | Command | Result |
|---|---|---|
| A (wrapper, unit) | `.venv/bin/python -m pytest -q tests/test_makepkg_wrapper.py -k "replaced or shadowed or locate_real or revalidate or rechecks"` | `7 passed, 135 deselected` (exit `0`) |
| A (recovery tools, unit) | `.venv/bin/python -m pytest -q tests/test_recovery.py -k "replaced or typed_confirmation or target_state or disk_sequence or trusted_signatures or arch_chroot"` | `10 passed, 59 deselected` (exit `0`) |
| B (review tokens) | `.venv/bin/python -m pytest -q tests/test_makepkg_wrapper.py -k "review_token or acceptance or hard_blocker or expired_review or one_time"` | `15 passed, 127 deselected` (exit `0`) |
| B (report binding) | `.venv/bin/python -m pytest -q tests/test_ui_actions.py::test_report_binding_matches_exact_bytes tests/test_instruction_cli_binding.py` | `9 passed` (exit `0`) |
| B (root broker / exact grant) | `.venv/bin/python -m pytest -q tests/test_agent.py -k "confirmation or broker or capability or grant or replaced_identity"` | `7 passed, 168 deselected` (exit `0`) |
| B (capability ceiling) | `.venv/bin/python -m pytest -q tests/test_agent.py -k "command_policy or escalation or access_ceiling or followup_agent_command or command_approval or decline"` | `129 passed, 46 deselected` (11 distinct tests, parametrized) (exit `0`) |
| C (repair / rollback) | `.venv/bin/python -m pytest -q tests/test_incident_repairs.py tests/test_recovery.py -k "repair or restore or rollback or recompute or remount"` | `25 passed, 61 deselected` (exit `0`) |
| C (cited node IDs) | The nine explicit node IDs listed in `evidence/test-results/2026-11-09-baseline.md` §6 (recovery metadata, target selection, failure evidence, environment scrubbing) | `9 passed` (exit `0`) |

These are unit-level probes with injected temporary paths. They are not
privilege-boundary exploit tests, and their passing does not establish that a
real privileged path is safe.

## Deliberately not executed

| Item | Why |
|---|---|
| Symlink or rename replacement at a real trusted executable path | Would touch host system paths. Needs a disposable VM with a controlled root filesystem and owner approval. |
| Concurrent TOCTOU race against `makepkg`, the root broker, or recovery tools | Needs an adversary process coordinated with the exact validation/exec window in a disposable environment. |
| Real second-process stolen-capability replay | Needs a genuinely privileged broker boundary; simulating it in one pytest process cannot prove cross-process isolation. |
| Compromised recovery target, USB write, or booted recovery image | Destructive/privileged and explicitly excluded by this card. |
| Kernel-level privilege inheritance (`no_new_privs`, capabilities, groups) | Not covered by the existing environment-scrubbing tests; requires a disposable VM. |

## What would close the largest gaps

A later, owner-approved card could provision a disposable Arch VM and add a
small harness that: (1) creates and swaps a symlink at a fake trusted-tool root
with a controlled revalidation window, (2) starts a second unprivileged process
against the broker with a stolen capability file, and (3) boots a simulated
target to exercise recovery selection and rollback. Those tests must carry the
same fail-closed assertions used here and must record actual command output.
Until then, the corresponding rows remain `NOT EXECUTED` or `OUT OF SCOPE`,
not "covered".
