# R5/R7 recovery hardening — implementation record

- Card: `t_420c0869` (worker). Application code plus rootless tests only.
- Baseline: `main` at `a7a1ffb` ("Harden isolated-build cleanup identity and
  status handling"). The pre-existing uncommitted edits to `AGENTS.md` and
  `docs/RELEASE_CHECKLIST.md` were not read for this change, not modified, and
  are not part of it.
- Design basis: `design/recovery-hardening-r5-r7.md` (corrected design) with
  `design/review-recovery-hardening-r5-r7.md` (CHANGES REQUESTED). This record
  does **not** claim the review approved the design or this implementation.
- No version bump, packaging edit, release note, commit, tag, push, AUR
  publication, ISO/UKI build, or recovery action was performed. No `sudo`,
  `arch-chroot`, `pacman`, `bootctl`, `sbctl`, `ukify`, or `snapper` was run.

> **Rework revision (card `t_e8730abc`, after Reviewer gate `t_c2dc2072`).**
> Sections 1–8 record the original candidate and its original run. Section 9
> records the four blocking corrections, the changed executor progress
> behaviour, the added behavioural tests, the corrected file pins and the
> re-run gates for the current candidate. Where the two differ, §9 is
> authoritative. Neither section is a review, security, release or
> recovery-gate approval.
>
> **Rework revision 3 (card `t_f4425960`, after Reviewer re-gate `t_758bdd26`).**
> Section 10 records the corrected caller-progress ownership, the truthful
> backup outcome, the new ordered-trace regressions, the corrected byte pins
> and the re-run gates. Where §9 and §10 differ, §10 is authoritative.
> §9.1's plan-level B2 claim is superseded: preflighting an action's host tools
> does not by itself keep a later executor capture from reusing the first-use
> text. This record is not a review, security, release or recovery-gate
> approval, and it does not amend any earlier completion run.

## 1. Files changed

| File | Change |
|---|---|
| `aurascan/core/trusted_tools.py` | Adds `HOST_TOOL_FIRST_USE_MESSAGE` (fixed `M0` text) and `require_trusted_system_tool(name)` (`trusted_tools.py:102`), which captures the fixed `/usr/bin/<name>` identity through `capture_trusted_system_tool` with a resolver that never consults `PATH`, then calls `revalidate_trusted_system_tool` and returns the tool. Raises `TrustedToolError` on absence or any unsafe identity; no PATH fallback. |
| `aurascan/core/recovery_repairs.py` | R5: module-private `SNAPSHOT_ID_RE` and `_validated_snapshot_id` (`recovery_repairs.py:114`), used at the start of both snapshot executors. R7: fixed-path trust capture/revalidation at every ROOT/PROBE/TARGET site, the per-site later-use messages, the `_fresh_action` target-pacman precondition, and `shutil.which("aurascan")` removal. |
| `aurascan/core/recovery_boot.py` | `ukify`, `bootctl`, `sbctl` (probe, sign, verify) and GRUB host generator / `arch-chroot` now run only through the fixed-path capture; optional probes degrade through their existing absence paths; later-use failures restore what the existing code restores. |
| `tests/test_recovery.py` | Adds the R5 validator/executor matrix, `_fresh_action` poisoned-id controls, and the R7 executor tests (first/later use, argv[0], cleanup, message preservation, systemd-boot refusal, target-pacman gate). Existing tests updated to inject the trust seam and expect absolute argv[0]. |
| `tests/test_recovery_boot.py` | Adds image/`ukify`, Secure Boot probe, `sbctl` sign/verify, and GRUB entry first/later-use tests; existing ukify/sbctl/GRUB tests inject the seam. |
| `tests/test_trusted_tools.py` | New rootless suite for `require_trusted_system_tool`: fixed path, hostile `PATH`, missing tool, traversing name, revalidation, resolver mismatch, unsafe path components, no cached identity. |

`aurascan/core/recovery.py`, `aurascan/core/recovery_cli.py`, packaging
metadata, version declarations, recovery assets and release notes are
untouched (`git status --short aurascan/core/recovery.py
aurascan/core/recovery_cli.py packaging pyproject.toml` shows no change).

## 2. R5 — exact behavior added

`_validated_snapshot_id(value)` (`recovery_repairs.py:114-138`):

- `type(value) is int` only: `0 <= value < 10**19` is checked **before** any
  conversion; the accepted result is `str(value)`. `10**19`, 20-digit and
  larger integers (including `10**5000`) return `""` without ever being
  stringified, so no int→str digit limit can raise.
- `type(value) is str` only: `SNAPSHOT_ID_RE.fullmatch` (`0` or
  `[1-9][0-9]{0,18}`); `"0"` and `0` both canonicalize to `"0"`.
- `bool`, `str`/`int` subclasses, floats, bytes, collections and arbitrary
  objects return `""`; no `__str__`/`__repr__`/conversion hook is invoked.

Consumption (before any path join or argv construction):

- `_execute_snapshot_test` (`recovery_repairs.py:919-921`): validates first,
  then keeps the existing `(root / f".snapshots/{snapshot_id}/snapshot").is_dir()`
  check and the exactly preserved `"Snapshot validation failed."`.
- `_execute_snapshot_restore` (`recovery_repairs.py:980-985`): validates first,
  refuses with the exactly preserved `"Snapshot restore prerequisites changed."`
  before the `root / f".snapshots/{snapshot_id}/snapshot"` join; the validated
  canonical string is the only value used in the path join, the `snapper
  rollback` argv and the result messages.

The accepted language is a documented fail-closed **narrowing**: a canonical
20-digit id that `recovery.py` can normalize and emit is refused by both
executors (pinned by `test_producer_overlong_snapshot_id_is_a_fail_closed_narrowing`).

## 3. R7 — site map actually implemented

Every call below is a fresh capture plus immediate revalidation; the executed
`argv[0]` is `tool.path` (`/usr/bin/<name>`) and every other argv element is
unchanged. Bare-name command lists (`bootloader_reinstall_commands`) and the
`_trusted_arch_chroot_tools` / `_trusted_target_binary` gates are byte-for-byte
unchanged.

`aurascan/core/recovery_repairs.py`:

| Site | Behavior |
|---|---|
| `_package_manager_running` | captures `ps`; capture failure returns `True` (existing conservative `code != 0` behavior, `:383-390`). |
| `_pacman_transaction_preconditions` | entry preflight `pacman-conf` → `(False, M0)`; every query (initial 2 + 2 per repository, ≤50 repositories) re-captures `pacman-conf`; a capture failure counts completed queries, so only a failure *before the first query* returns `(False, M0)`, and any later one returns `(False, PACMAN_CONF_TRUST_LATER_MESSAGE)` (`:403-447`). |
| `_prepare_write_target` | preflights `findmnt` and `mount` before the first query → `(False, M0)`; each query/re-mount/verify re-captures then uses `tool.path`; failures map to `FINDMNT_QUERY_TRUST_LATER_MESSAGE`, `MOUNT_TRUST_LATER_MESSAGE` (or the retained-earlier-remount variant) and `FINDMNT_VERIFY_TRUST_LATER_MESSAGE` (`:447-500`). |
| `_unit_still_failed` | captures `journalctl`; failure returns `False` (existing `code not in {0,1}` value, `:507-519`). |
| `_fresh_action` | preflights `journalctl` for the service-disable branch and returns `None`; the `exact_package_reinstall` probes now require `_trusted_target_binary(rooted(root, "/usr/bin/pacman"), root)` and re-capture `arch-chroot` before each of `-Qm`/`-Qkk`; any trust failure returns `None` (`:553-586`). |
| `_execute_stale_lock` | entry preflight `ps`+`pacman` → `refused`/M0; after lock removal a fresh `pacman` capture fails → lock restored from the existing backup (`rolled_back`, exact restored message) or `failed` with the retained-backup message (`:678-724`). |
| `_execute_cache_cleanup` | captures `paccache` immediately before its single use → `refused`/M0 (`:735-738`). |
| `_execute_pacman_action` | entry preflight `pacman-conf`+`arch-chroot` → `refused`/M0; `pacman-key --verify` and the transaction command each re-capture `arch-chroot` (`refused`/`PACMAN_KEY_TRUST_LATER_MESSAGE`, `failed`/`PACMAN_TRANSACTION_TRUST_LATER_MESSAGE`) (`:742-809`). Target `pacman`/`pacman-key` gate messages unchanged. |
| `_execute_initramfs` | entry preflight `arch-chroot` before the space check and backups → `refused`/M0; the generator command re-captures → `failed`/`INITRAMFS_TRUST_LATER_MESSAGE` with the existing backup records retained when at least one image was backed up, or `refused`/M0 with no backup path and `rollback_available=False` when the image set was empty (`:847-905`). |
| `_execute_config_drift` | fixed `/usr/bin/aurascan` (`shutil.which` fallback dropped) → `refused`/M0 (`:883-888`). |
| `_execute_dkms` | `arch-chroot` capture after the target `dkms` gate → `refused`/M0 (`:897-899`). |
| `_execute_disable_service` | `systemctl` capture → `refused`/M0 (`:910-912`). |
| `_execute_snapshot_test` | preflight `bootctl` before the entry write → `refused`/M0; the execution capture re-runs after the entry was `os.replace`d, removes it and returns `failed`/`SNAPSHOT_TEST_TRUST_LATER_MESSAGE` (`:946-966`). |
| `_execute_snapshot_restore` | preflight `arch-chroot` before any command; the `snapper create` and `snapper rollback` executions each re-capture; the rollback capture failure returns `failed`/`SNAPSHOT_RESTORE_TRUST_LATER_MESSAGE` with the created pre-recovery snapshot retained (`:985-1028`). |
| `_execute_bootloader` | preflights host `arch-chroot` for Limine/GRUB *before* the re-inspection, so a first-use refusal really has zero commands and zero target mutations → `refused`/M0; each loop command re-captures `arch-chroot` (failure at command *k* runs the existing `_restore_backup_records` and returns the exact restored/retained partial-progress message; a failure before command 1 returns `failed` with `BOOTLOADER_TRUST_BEFORE_COMMAND_BACKED_UP_MESSAGE`/`..._NO_BACKUP_MESSAGE` and retains any backups) (`:1080-1170`). The systemd-boot `bootctl` recipe still fails `_trusted_arch_chroot_tools` and refuses before any tool runs. |
| `export_recovery_report` | preflights `findmnt`+`lsblk` → `(None, M0)`; `findmnt` and `lsblk` each re-capture before use; `lsblk` failure after the `findmnt` probe → `(None, EXPORT_LSBLK_TRUST_LATER_MESSAGE)` and no export is written (`:1278-1302`). |

`aurascan/core/recovery_boot.py`:

| Site | Behavior |
|---|---|
| `validate_recovery_image` | `which("ukify")` remains the absence gate; a present tool is captured through `/usr/bin/ukify`. Absent **or untrusted** yields the exact R8 string `"ukify is unavailable; the recovery image cannot be structurally validated."` and no runner call (`:347-365`). |
| `detect_secure_boot` | `bootctl` probe: absent or untrusted falls through to the existing efivars fallback (`:385-399`). |
| `sbctl_owner_key_ready` | absent or untrusted returns the existing `(False, "sbctl is unavailable.")` (`:420-427`). |
| `sign_recovery_image` | absent/untrusted at entry → existing `unavailable`/"Secure Boot is enabled but sbctl is unavailable."; status probe unchanged; the sign and verify commands each re-capture `sbctl`; post-sign capture failure returns the truthful "signed but unverified" `failed` result with the existing `command=` attribution (`:451-486`). |
| `install_bootloader_entry` | host `grub-mkconfig` and non-`/` `arch-chroot` are captured after the existing absence checks (`unavailable` + M0 when present-but-untrusted); the regeneration call re-captures after the script write and output backup, and its failure runs the byte-identical restoration block then returns `failed` with the restored message (`:576-632`). |
| `recovery_image_status` | `sbctl verify` probe: absent or untrusted leaves `signed` False so the existing "signature was not verified" error fires (`:699-711`). |
| `inspect_usb_device` | unchanged (already on `capture_trusted_system_tool` / `revalidate_trusted_system_tool`). |

## 4. Decisions and deviations (all deliberate; nothing silently widened)

1. **`HOST_TOOL_FIRST_USE_MESSAGE` location.** Defined once in
   `trusted_tools.py:19` and imported by both executors, because
   `recovery_repairs.py` imports `recovery_boot.py` and the reverse import
   would be circular. The text is exactly §5.2.3 `M0`.
2. **`_execute_pacman_action` preflight scope.** §5.2.3's parenthetical lists
   `pacman-conf`, `arch-chroot`, target `pacman` and target `pacman-key`
   "at entry". The entry preflight covers the two host tools; the target
   `pacman` gate stays at its original position (`recovery_repairs.py:751`)
   and the target `pacman-key` gate in the exact-package branch
   (`recovery_repairs.py:788`). Preflighting `pacman-key` for every recipe
   would refuse `complete_pacman_transaction` on a target that has no keyring
   helper the recipe never executes, so the card's operative rule ("every host
   tool an action needs before the first mutation") was applied per recipe.
   All existing target-gate messages are preserved and tested.
3. **Additional truthful later-use messages not enumerated in §5.2.3.** The
   code has trust boundaries the table does not name; each new message avoids
   zero-progress wording:
   - `MOUNT_TRUST_LATER_REMOUNTED_MESSAGE` — a second mountpoint's `mount`
     capture fails after an earlier remount was retained.
   - `PACMAN_KEY_TRUST_LATER_MESSAGE` — `arch-chroot` capture fails before
     `pacman-key --verify` after the policy queries ran.
   - `"The sbctl owner-key status was queried, but sbctl failed trust
     revalidation before signing; the recovery image was not modified."`
     (`recovery_boot.py:462-469`).
   - GRUB non-`/` root later-use variant naming `arch-chroot` instead of
     `grub-mkconfig` (`recovery_boot.py:618-626`).
4. **Snapshot-restore later-use wording.** The §5.2.3 text names `snapper`,
   while the failing capture is the host `arch-chroot` that would launch it.
   The exact design text is used; the target `snapper` gate remains the
   entry-time `_trusted_target_binary` check because §5.2.2.5 keeps target
   semantics unchanged.
5. **`_prepare_write_target` M0 truthfulness.** A `completed_queries` counter
   distinguishes "no query has run" (M0) from "a query already ran"
   (`FINDMNT_QUERY_TRUST_LATER_MESSAGE`), so `M0` is never emitted after a
   command.
6. **`which` parameters retained as presence gates.** `validate_recovery_image`,
   `detect_secure_boot`, `sbctl_owner_key_ready`, `sign_recovery_image`,
   `install_bootloader_entry` and `recovery_image_status` keep their `which`
   keyword because `recovery_cli.py` passes it and must not be modified. The
   value returned by `which` is never executed: execution always uses the
   fixed-path capture, and a hijacked `PATH` therefore turns into degradation
   instead of execution.
7. **Existing tests were updated to inject a fake trusted identity and expect
   the absolute argv[0].** Without this, those tests would depend on the test
   host having `/usr/bin/arch-chroot`, `/usr/bin/ukify`, `/usr/bin/sbctl`,
   etc., and would exercise PATH-style resolution the change removes.

## 5. Tests added (rootless only)

`tests/test_recovery.py` (163 passed in the original candidate; 177 in the
corrected candidate — see §9.3):

- R5: paired integer/string zero and ordinary ids; 19-digit boundary and
  `10**18`; refusal matrix (bool, float, bytes, collections, signs, leading
  zeros, newline/tab/backslash, Unicode decimal/superscript/full-width,
  traversal/separators, 20-digit int/string, `10**19`, `10**5000`); spy/raising
  `__str__` objects; `str`/`int` subclasses; producer overlong narrowing;
  both executors refuse invalid ids with their exact messages and zero runner
  calls; a positive one-shot entry fixture with `/usr/bin/bootctl` and an
  integer id; `_fresh_action` poisoned-id no-match plus valid-id control.
- R7: first-use refusal for stale lock, cache cleanup, config drift, DKMS,
  initramfs, snapshot test, snapshot restore, pacman action, bootloader, plus
  `_package_manager_running`'s and `_unit_still_failed`'s conservative values,
  `(False, M0)` from `_pacman_transaction_preconditions`, and the
  `_prepare_write_target` / `export_recovery_report` / `_fresh_action` return
  shapes (including `_fresh_action` returning `None` after a later capture
  failed once a probe command had run).
- R7 later-use: pacman-conf query boundary; findmnt query, mount and
  findmnt-verify boundaries; lock removal then pacman revalidation (restored
  and retain-on-restore-failure); initramfs backups retained; snapshot entry
  written then removed; pre-recovery snapshot created and retained; pacman-key
  and transaction boundaries; GRUB command 2 after command 1 with
  `_restore_backup_records` exercised; lsblk after findmnt.
- Message/argv preservation: ordinary applied/failed messages, the 4000-char
  redacted `output_excerpt`, absolute argv[0] for
  bootctl/systemctl/paccache/aurascan/mount/findmnt/lsblk/pacman-conf/
  arch-chroot, systemd-boot refusal with zero commands and bare-name preview,
  target keyring gate message, plan `"Fresh root-side revalidation no longer
  approves this action."`.

`tests/test_recovery_boot.py` (46 passed in the original candidate; 47 in the
corrected candidate): exact R8 string equality for an
untrusted `ukify` with zero runner calls; trusted `ukify` argv; `bootctl`
present-but-untrusted → efivars fallback; `sbctl` absent and untrusted →
existing tuple; `recovery_image_status` unsigned + error; sign unavailable /
refused-after-status / unverified-after-sign / success argv sequence; GRUB
entry first-use `unavailable`+M0 before any write and later-use restoration of
the previous script and configuration.

`tests/test_trusted_tools.py` (9 passed): fixed path, hostile `PATH` with a
shadowing wrapper (and `shutil.which` forbidden), missing tool, traversing
name, immediate revalidation, resolver mismatch, unsafe relative/`..`/
non-root-owned paths, and no cached identity across calls.

## 6. Commands run and observed results (original candidate; superseded by §9.5)

All commands were run from the working tree at `/home/arawn/Documents/Other
Projects/AuraScan`.

| Command | Result |
|---|---|
| `python -m compileall -q aurascan tests tools` | exit 0 |
| `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q tests/test_recovery.py tests/test_recovery_boot.py tests/test_trusted_tools.py` | exit 0 — **218 passed** in 1.67s (163 + 46 + 9) |
| `.venv/bin/python tools/audit_presenter_coverage.py --strict` | exit 0 (279 rule IDs, 214 optional metadata, 18 fallback, **0 MEDIUM+ fallback**) |
| `.venv/bin/python tools/audit_presenter_coverage.py --strict-medium` | exit 0 (same counts) |
| `git diff --check` | exit 0 |
| `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q --ignore=.worktrees --ignore=packaging` | exit 1 — **6048 passed, 5 skipped, 1 failed** in 270.26s |

The single full-suite failure is the pre-existing external fixture mismatch
`tests/test_injection_golden.py::test_golden_head_matches_the_live_anticopy_head`
(`golden["anticopy_head"] = 1860024b…` vs the live AntiCopy checkout `5e753d08…`).
It is unrelated to R5/R7 and is **not** green; it is reported as a failure, not
waived. No other test failed.

## 7. `not_verified`

- Real root-owned tool identity: the `os.geteuid() == 0` owner/writability
  branch of `_trusted_tool_stat` and any actual `/usr/bin` revalidation were
  exercised only through fake identities and unit seams. No privileged
  revalidation was run.
- The recovery image's actual `/usr/bin/<name>` layout for every ROOT/PROBE
  tool (design §6.2.18) — unit tests cannot see the image.
- Booted target-disk scenarios (§6.2.19): snapshot confirmation/restore,
  initramfs rebuild, service disable, pacman transaction, cache cleanup,
  Limine/GRUB reinstall on a booted disk. Not run.
- ISO, local UKI, Secure Boot / OVMF owner-key, serial-readiness, privacy and
  size gates. Not run.
- Real `arch-chroot`, `pacman`, `pacman-conf`, `paccache`, `bootctl`, `sbctl`,
  `ukify`, `grub-mkconfig`, `snapper`, `systemctl`, `journalctl`, `mount`
  behavior under the substituted argv[0]. Fake runners only.
- The check-to-exec TOCTOU residual and the unbounded `_run` capture residual
  (design §4.2) are **not** closed by this change; their disposition remains
  with Red (`t_1dc663ac`).
- Whether the new finding-driven message strings need additional presentation
  or documentation treatment beyond the preserved-message tests; no rule IDs
  were added or changed, so the presenter audits are unaffected (both run and
  passed).
- Producer/executor snapshot-id parity (design Appendix A1) is explicitly out
  of scope; the executor narrowing is fail-closed but `recovery.py` still
  emits overlong canonical ids.

## 8. Follow-ups left out deliberately

- Image-layout gate (§6.2.18) must assert every fixed path before this change
  can be relied on in a recovery release.
- Booted target-disk scenarios (§6.2.19) remain mandatory for the
  recovery-bearing release; the systemd-boot reinstall refusal must be shown
  as refused, not working.
- Red's security disposition of the two transport residuals (`t_1dc663ac`).
- Separate producer-bound snapshot-id change if exact producer/executor
  identity is later required (design Appendix A1, own review).
- No review, release, or recovery-gate approval is claimed by this record.

## 9. Rework after Reviewer gate `t_c2dc2072`

Reviewer card `t_c2dc2072` returned CHANGES REQUESTED with four blocking
findings. This section records the corrections in the working tree. It is a
work record, not a review disposition; the authoritative sourced handoff is the
new completion metadata on this card, not this prose.

### 9.1 Corrections

**B1 — authoritative evidence payload.** A new completion payload for this card
carries `source`, rerunnable `evidence` and `confidence` on every claim-bearing
object (including nested findings, test and command records), plain
`changed_files`, exact `commands_run` records with cwd and exit, observed
`tests_passed`, explicit `not_verified` and `followups`. The historical
`t_420c0869` run 294 completion is not edited, amended, or retroactively
repaired; this record and the new payload do not claim otherwise.

**B2 — no first-use wording after caller progress.**

- `_execute_bootloader` now preflights `arch-chroot` for Limine/GRUB before
  `inspect_recovery_target` runs its `findmnt` query
  (`recovery_repairs.py:1081-1085`). A failure there returns `refused`/M0 with
  zero runner commands and zero target mutations. A revalidation failure before
  command 1 (after inspection and backups) returns `failed` with
  `BOOTLOADER_TRUST_BEFORE_COMMAND_BACKED_UP_MESSAGE` or
  `..._NO_BACKUP_MESSAGE` (`:1114-1133`), retaining any backups and never
  claiming that a reinstall command ran. The systemd-boot recipe keeps the
  unchanged `_trusted_arch_chroot_tools` refusal; the executor does not
  arch-chroot-preflight a `bootctl` recipe.
- `execute_recovery_plan` now computes the host tools required by every
  runnable action (`ACTION_REQUIRED_HOST_TOOLS` / `_action_required_host_tools`,
  `:1219-1252`) and passes them to `_prepare_write_target`
  (`:1275-1279`). `_prepare_write_target` preflights them after the
  running-root/root-uid refusals and before any `findmnt` query, remount, or
  recovery-state creation (`:457-478`). A missing action tool therefore refuses
  the plan with M0, zero commands, no remount and no `run_root`, instead of
  remounting and creating state before the executor's first-use refusal.
- Assumption recorded: the plan preflights the union of tools for all runnable
  actions. If a later action's tool is unavailable, the whole plan refuses
  before mutating anything rather than applying earlier actions and then
  reporting a first-use message. This is the fail-closed reading of the
  zero-progress promise.

**B3 — zero-query and zero-image classification.**

- `_pacman_transaction_preconditions` counts completed queries
  (`:426-452`). A `pacman-conf` capture failure before the first query has run
  returns `(False, M0)`; a failure after at least one query returns the
  unchanged `PACMAN_CONF_TRUST_LATER_MESSAGE`.
- `_execute_initramfs` selects its trust-failure branch from this action's
  backup records (`:880-895`). With no initramfs image to back up it returns
  `refused`/M0, `backup_path=""`, `rollback_available=False`, no backup
  directory and no command. With images backed up it keeps the exact
  `INITRAMFS_TRUST_LATER_MESSAGE`, `backup_path=str(backup_root)` and
  `rollback_available=True`.

**B4 — behavioural, inert oracles.**

- `tests/test_recovery.py` now has a real unit file plus `var/log/journal`
  fixture and a journal runner that emits an actual failure line. The journalctl
  positive test proves the fixed-path command runs and the result is `True`.
  The negative test asserts `False`, zero runner commands and that the trust
  seam was reached (`["journalctl"]`). A calibration test replaces only the
  rejecting seam with a permissive one and asserts the shared negative helper
  now fails.
- The `_fresh_action` journalctl pair is the same shape: a positive fixture
  where the action is returned with exactly one journalctl command, a negative
  case with zero commands and the seam reached, and a permissive-seam
  calibration.
- `tests/test_recovery_boot.py` passes a trapping runner in the first-use GRUB
  test and a recording runner in the later-use test, and asserts the injected
  seam calls and the exact zero-command prefix. A host-generator test exercises
  the real `root=Path("/")` branch with `rooted` mapped into a temporary tree
  and asserts `["/usr/bin/grub-mkconfig", "-o", <mapped output>]`.
- New executor coverage: zero-query pacman-conf, zero-image initramfs, plan
  preflight before remount/state, plan control after trust succeeds, bootloader
  preflight before real inspection, bootloader inspection after trust succeeds,
  later restoration failure with retained backups, positive pacman and DKMS
  fixed-path argv, and direct `required_tools` preflight.
- Optional LOW nits in the review: (a) the unchanged-script GRUB edge still
  rewrites the script and uses the mandated "script was written" message —
  reviewed and deliberately not changed, because it alters no script or
  configuration bytes and no command executes, while changing it would alter
  the design-mandated restoration block and message-preservation control;
  (b) the absent-ingress `scan.json` record is a reviewer-side evidence gap, not
  actionable in this implementation card; (c) the coarse absent-versus-untrusted
  fixtures in `tests/test_trusted_tools.py` and `tests/test_recovery_boot.py`
  are kept as coarse negative controls and are not evidence for every
  final-file ownership/mode/link check; controlled lstat/access identity
  fixtures remain a non-blocking coverage improvement. None of these is treated
  as a blocker.

### 9.2 Preserved controls (re-verified by the re-run suite)

R5's total exact-built-in validator and both original invalid-ID messages;
fixed `/usr/bin` capture with no `PATH` fallback; `_trusted_target_binary` and
`_trusted_arch_chroot_tools` AST-identical to baseline `a7a1ffb`; the R8 ukify
unavailable string; the systemd-boot reinstall refusal with zero commands and a
bare-name preview; preview/recipe command lists; `argv[1:]` preservation with
only `argv[0]` replaced; and every ordinary applied/failed/rolled-back message.

### 9.3 Tests

Corrected focused counts: `tests/test_recovery.py` 177, 
`tests/test_recovery_boot.py` 47, `tests/test_trusted_tools.py` 9 — 233 total
(15 net new; two journalctl tests replaced with behaviourally valid versions).

Added or rewritten in `tests/test_recovery.py`:

- `test_unit_failure_check_reads_a_failing_journal_through_the_trusted_path`
- `test_unit_failure_check_is_conservative_when_journalctl_is_untrusted`
- `test_unit_failure_negative_oracle_fails_when_the_trust_boundary_is_bypassed`
- `test_fresh_action_requires_the_trusted_journalctl_and_a_real_journal`
- `test_fresh_action_preflights_journalctl_and_returns_none`
- `test_fresh_action_negative_oracle_fails_when_the_trust_boundary_is_bypassed`
- `test_pacman_preconditions_first_query_capture_failure_returns_m0`
- `test_initramfs_zero_image_trust_failure_refuses_without_claiming_backups`
- `test_plan_preflights_action_tools_before_remount_or_state_creation`
- `test_plan_preflight_control_runs_after_trust_succeeds`
- `test_bootloader_preflights_the_host_tool_before_its_inspection_runs_a_command`
- `test_bootloader_inspection_runs_after_the_trust_preflight_succeeds`
- `test_bootloader_later_trust_failure_reports_retained_backups_when_restoration_fails`
- `test_pacman_action_uses_the_fixed_path_host_tools_for_every_argv`
- `test_dkms_autoinstall_uses_the_fixed_path_host_arch_chroot`
- `test_prepare_write_target_preflights_caller_required_tools_before_queries`

Added in `tests/test_recovery_boot.py`:

- `test_grub_entry_host_generator_uses_the_fixed_grub_mkconfig_path`

Both existing GRUB trust tests now inject inert runners and assert seam calls /
zero commands.

### 9.4 Corrected candidate pins (baseline `a7a1ffb`)

| File | SHA-256 |
|---|---|
| `aurascan/core/trusted_tools.py` | `2e0b95400612f39e0b627ad44de43a155cdc2dc259bdc537cd8b584a0afaf8c5` |
| `aurascan/core/recovery_repairs.py` | `72fc606a3fe5464f324f271b5cce7d975e23e071cf48585049027b1ea87ec52e` |
| `aurascan/core/recovery_boot.py` | `8edf5fc68b9d3801110c14c1a83921593cccfeab1c57c0f106014fc790ee09ec` |
| `tests/test_recovery.py` | `49d754daeb1470186cb92e4f6587c04b6b79afa8c713abbf32b5135f5f320f1d` |
| `tests/test_recovery_boot.py` | `11d40b5d960e815527cf06977e81d7d7ed276a1cf1b73c9bcc0d014a29309a75` |
| `tests/test_trusted_tools.py` | `72831abc1508f74c6580ecb971c6a0b25117b670d8b3beae6b1a036c26b86135` |
| `findings/r5-r7-implementation.md` | pinned in the completion metadata after this edit |

`aurascan/core/recovery.py`, `aurascan/core/recovery_cli.py`, `AGENTS.md`,
`docs/RELEASE_CHECKLIST.md`, `design/`, `packaging/`, version/release-note files
and assets are not part of this change. `AGENTS.md` and
`docs/RELEASE_CHECKLIST.md` keep their pre-existing uncommitted edits
(mtimes 2026-11-10 10:51, before this card started).

### 9.5 Gates re-run on the corrected candidate

All from `/home/arawn/Documents/Other Projects/AuraScan`, with
`PATH=/usr/bin:/bin` for pytest (the documented gate environment; the session
PATH puts `/usr/sbin` first, which makes the pre-existing
`recovery_cli` USB `findmnt`/`lsblk` presence gate reject `/usr/sbin/…`):

| Command | Observed |
|---|---|
| `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q tests/test_recovery.py tests/test_recovery_boot.py tests/test_trusted_tools.py` | exit 0, 233 passed |
| `python -m compileall -q aurascan tests tools` | exit 0 |
| `.venv/bin/python tools/audit_presenter_coverage.py --strict` | exit 0 |
| `.venv/bin/python tools/audit_presenter_coverage.py --strict-medium` | exit 0 |
| `git diff --check` | exit 0 |
| `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q --ignore=.worktrees --ignore=packaging` | exit 1, 6063 passed, 5 skipped, 1 failed (external AntiCopy golden-head at `tests/test_injection_golden.py:70`, unchanged from baseline) — **NOT green** |
| `git diff --exit-code a7a1ffb -- tests/test_injection_golden.py tests/fixtures/injection_golden/spans.json` | exit 0 (failure's test and golden bytes unchanged) |
| `TMPDIR=/home/arawn/.hermes/profiles/worker/cache/scratch/r5r7 PATH=/usr/bin:/bin .venv/bin/python /home/arawn/.hermes/profiles/worker/cache/scratch/r5r7/rework_probes.py` | exit 0; all six corrected counterexamples and the permissive-seam calibrations hold; function-AST identity for `_trusted_target_binary`/`_trusted_arch_chroot_tools` |

Runtime Python: `.venv` 3.14.8 for pytest; `python` 3.14.9 for compileall.
No Python 3.8 run is claimed.

### 9.6 `not_verified` for the corrected candidate

Everything in §7 still applies. In addition:

- Real euid-0 invocation of every changed preflight and every `arch-chroot` /
  `bootctl` revalidation; root-owned file identities and ACL/permission
  transitions. Fake trust identities and fake runners only.
- Actual recovery-image `/usr/bin/<name>` contents for all host tools.
- Booted target-disk actions (snapshot restore, initramfs/dkms rebuild, pacman
  transactions, service disable, bootloader reinstall), real `grub-mkconfig`
  execution, and any real USB write.
- ISO/UKI/Secure Boot/serial/privacy/size gates and booted network scenarios.
- The race between a successful preflight and a later identity change. The
  preflight/cleanup paths are covered; the atomic check-to-exec closure remains
  a Red-owned residual (design §4.2), not changed here.

### 9.7 Follow-ups

- Independent Reviewer re-gate on these exact pins and the new sourced handoff;
  this record is not acceptance.
- Red security disposition of the unchanged transport residuals.
- Image-layout and booted target-disk gates before any recovery-bearing release.
- Optional GRUB idempotent-restoration nit, if the design owner wants the
  message/restoration block changed.
- Producer/executor snapshot-id parity (design Appendix A1).

## 10. Rework revision 3 — caller progress, backup truthfulness, native evidence

Card `t_f4425960`, scoped correction after Reviewer re-gate `t_758bdd26`
(`design/review-r5-r7-implementation-regate.md`, findings 1–3). Baseline/HEAD
is unchanged at `a7a1ffbec99f6118c32a1ca14f96cf4d8082b929`. This revision
changed exactly two files: `aurascan/core/recovery_repairs.py` and
`tests/test_recovery.py`. The other four candidate files
(`aurascan/core/trusted_tools.py`, `aurascan/core/recovery_boot.py`,
`tests/test_recovery_boot.py`, `tests/test_trusted_tools.py`) are
byte-identical to the pins the Reviewer recorded.

No design report, `recovery.py`, `recovery_cli.py`, packaging, version,
release-note or AntiCopy golden evidence was edited. `AGENTS.md` and
`docs/RELEASE_CHECKLIST.md` keep their pre-existing unrelated edits.

### 10.1 Finding 1 — progress ownership across the plan, freshness and executor

The reviewed candidate preflighted the plan's action tools but still let the
executor's own later fresh capture return `HOST_TOOL_FIRST_USE_MESSAGE` after
preparation commands, a writable remount and recovery-state creation. That
message is only true while nothing has run and nothing changed.

- `RepairProgress` (`recovery_repairs.py:137-162`) records the plan's command
  count, writable remounts and recovery-state creation; `mutations` and
  `advanced` expose whether any progress exists.
- `execute_recovery_plan` creates one tracker, wraps the caller's runner once
  (`:1435-1437`), passes the tracked runner to `_prepare_write_target`,
  `_fresh_action` and `execute_recovery_action`, records the remount in
  `_prepare_write_target` (`:616`) and records state creation after
  `run_root` is created (`:1454`).
- `_truthful_first_use_result` (`:1297-1324`) converts any executor result that
  still carries `HOST_TOOL_FIRST_USE_MESSAGE` into a `failed`
  partial-preparation result with the observed command/step counts when the
  tracker advanced. `execute_recovery_action` applies it to every allowlisted
  recipe (`:1327-1362`). Direct executor calls without a tracker keep their
  existing zero-progress semantics.
- Fresh per-use capture/revalidation is untouched: the plan preflight, the
  executor capture and each `_run` site still call
  `require_trusted_system_tool` freshly. No tool identity is cached or reused,
  and no recipe changed.
- The `paccache -r -k 2 -c <cache>` argv tail and its fixed
  `/usr/bin/paccache` prefix are asserted unchanged by the positive trace.

Observed with the rootless real-plan probe (inert runner, fake trust
identities, temporary target root, mocked effective UID; no real command):

- entry rejection: `refused`/M0, zero commands, no remount, no `run_root`;
- paccache failure on its second capture: four inert commands
  (`findmnt`, `findmnt`, `mount -o remount,rw`, `findmnt`), `run_root` and
  `manifest.json` present, `mounted_read_only=False`, status `failed`, and the
  partial-preparation message — no M0 in the returned result or the persisted
  manifest;
- already-writable preparation: zero commands, state creation recorded, same
  truthful `failed` result instead of M0;
- prior applied action: the later action's capture failure is `failed` with the
  prior command count, not a first use.

### 10.2 Finding 2 — restore failure versus verified retained backups

- `_retained_backup_records` (`recovery_repairs.py:416-448`) re-reads each
  recorded backup path, requires it inside the backup root, regular,
  non-symlink, the recorded size and the recorded SHA-256.
- `_loader_backup_outcome` (`:451-465`) selects the message,
  `rollback_available` and `backup_path` from `restored` plus those verified
  bytes:
  - restored: `"...backed-up loader files were restored."`,
    `rollback_available=True`, `backup_path=<backup_root>` (unchanged
    reviewed behaviour);
  - destination restore failed with verified bytes retained:
    `"...the destination restore failed, but the backed-up loader bytes were
    verified and retained."`, `rollback_available=True`,
    `backup_path=<backup_root>`;
  - absent/corrupt/unusable bytes:
    `"...no verified loader backup remains, so a rollback is not available."`,
    `rollback_available=False`, `backup_path=""`.
- The outcome is applied to the later trust-failure branch, the non-zero
  reinstall branch and the post-validation branch, and the pre-command-1
  branch now requires verified bytes before its "backed-up loader files were
  retained" wording (`_execute_bootloader:1211-1294`). No branch derives
  availability from a manifest record alone, and every failure branch stops
  before the remaining reinstall commands.
- The ordinary applied success message and the transport logic are unchanged.

### 10.3 Finding 3 — authoritative evidence

This card's completion payload is a new native completion, not a comment or an
amendment to `t_e8730abc` run296. Every claim-bearing nested record carries
`source`, rerunnable `evidence` and `confidence`; every `source: model` record
is `confidence: low`; `commands_run` entries include the exact command, cwd and
exit; `changed_files`, `tests_passed`, nonempty `not_verified` and `followups`
are present. The payload does not claim that the parent's empty native
run299 metadata was amended, does not claim a review/acceptance, and does not
claim any release or recovery gate.

### 10.4 Tests added or rewritten

`tests/test_recovery.py` (this revision):

- `PlanProbe` + `configure_plan_probe` + `cache_plan_fixture` — one ordered
  trust/runner/state trace shared by the plan regressions (`:2703-2767`).
- `test_plan_shared_trace_entry_rejection_is_zero_progress` (`:2770-2783`).
- `test_plan_shared_trace_positive_preparation_is_ordered` (`:2786-2814`) —
  asserts the exact ordered trust/runner/state sequence through remount, state
  creation, executor capture and the `paccache` repair suffix.
- `test_plan_shared_trace_later_capture_failure_reports_partial_preparation`
  (`:2817-2841`) — four inert commands, run directory and manifest present,
  `mounted_read_only=False`, non-M0 partial message in result and manifest.
- `test_plan_shared_trace_already_writable_state_creation_is_not_first_use`
  (`:2844-2863`).
- `test_plan_shared_trace_prior_action_progress_is_not_first_use`
  (`:2866-2888`).
- `bootloader_later_trust_fixture` (`:2934-2949`).
- `test_bootloader_later_trust_failure_does_not_claim_deleted_backups`
  (`:2952-2991`) — replaces the reviewed test that asserted retained backups
  after deleting them.
- `test_bootloader_later_trust_failure_does_not_claim_corrupt_backup`
  (`:2994-3033`) — same-size corrupt backup bytes fail verification.
- `test_bootloader_later_trust_failure_keeps_verified_backups_when_destination_restore_fails`
  (`:3036-3083`) — inert destination-write failure, backup bytes asserted by
  content, truthful message/path/rollback fields, one command only.

Focused total: 240 passed (`test_recovery.py`, `test_recovery_boot.py`,
`test_trusted_tools.py`). Seven tests were added and one defective test was
rewritten in this revision.

### 10.5 Corrected candidate pins (baseline `a7a1ffb`)

| File | SHA-256 |
|---|---|
| `aurascan/core/trusted_tools.py` | `2e0b95400612f39e0b627ad44de43a155cdc2dc259bdc537cd8b584a0afaf8c5` |
| `aurascan/core/recovery_repairs.py` | `5e58700491f4474d86bd43652694336d6ae35b5f4a55805eaaa9626f24345cd3` |
| `aurascan/core/recovery_boot.py` | `8edf5fc68b9d3801110c14c1a83921593cccfeab1c57c0f106014fc790ee09ec` |
| `tests/test_recovery.py` | `74606d67102e82329b90077feb859ba04fc7579c4d6e2af4fa336bb3fefc79e3` |
| `tests/test_recovery_boot.py` | `11d40b5d960e815527cf06977e81d7d7ed276a1cf1b73c9bcc0d014a29309a75` |
| `tests/test_trusted_tools.py` | `72831abc1508f74c6580ecb971c6a0b25117b670d8b3beae6b1a036c26b86135` |
| `findings/r5-r7-implementation.md` | pinned in this card's completion metadata after the final edit |

### 10.6 Gates re-run on this revision

All from `/home/arawn/Documents/Other Projects/AuraScan`:

| Command | Observed |
|---|---|
| `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q tests/test_recovery.py tests/test_recovery_boot.py tests/test_trusted_tools.py` | exit 0; 240 passed |
| `python -m compileall -q aurascan tests tools` | exit 0 |
| `.venv/bin/python tools/audit_presenter_coverage.py --strict` | exit 0 |
| `.venv/bin/python tools/audit_presenter_coverage.py --strict-medium` | exit 0 |
| `git diff --check` | exit 0 |
| `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q --ignore=.worktrees --ignore=packaging` | exit 1; 6070 passed, 5 skipped, 1 failed — **NOT green** |
| `PATH=/usr/bin:/bin TMPDIR=<worker scratch> .venv/bin/python <worker scratch>/rework_probes.py` | exit 0; entry rejection, positive preparation, later rejection, already-writable state creation and both backup cases hold; `REWORK_PROBES_COMPLETED` |

The only full-suite failure is
`tests/test_injection_golden.py:70::test_golden_head_matches_the_live_anticopy_head`:
the golden pins `1860024bb067b7aef6da542348c01c43bbb70754` and the external
checkout reports `5e753d0867d7823150adda3cdfde655184faf329`. The test and
golden fixture bytes are unchanged against baseline and are not repaired here.
This is an unsuccessful source gate, not a green run or a waiver.

Runtime: `.venv` Python 3.14.8 for pytest and probes; `python` 3.14.9 for
compileall. No Python 3.8 run is claimed.

### 10.7 `not_verified` and follow-ups

Everything in §7 and §9.6 still applies. In addition, this revision did not
verify:

- Real euid-0 execution of the changed plan or bootloader branches, real
  root-owned tool identities, ownership/ACL transitions or live
  identity-change races. Fake trust identities, a mocked effective UID and
  inert runners only.
- An actual recovery image's `/usr/bin/<name>` layout for every required and
  optional tool.
- Any real recovery action, mount/remount, bootloader reinstall, pacman
  transaction, snapshot, initramfs/DKMS rebuild, USB write, reboot or
  target-disk/network scenario.
- ISO/UKI/Secure Boot/serial/privacy/size gates, a release build, tag, push,
  package publication or CI.
- Python 3.8 runtime compatibility.
- The atomic pathname check-to-exec closure and capture-memory bound accepted
  by Red as documented residuals; this revision does not re-dispose them.

Follow-ups: Red owns the security disposition of the corrected candidate; the
owner must arrange a new independent Reviewer quality re-gate on these pins
and this card's native completion. No acceptance, build permission or recovery
gate is claimed here.
