# Attack-surface inventory — baseline `02ac13d` (AuraScan 0.15.0, rules 1.15.0)

Every claim is labelled `[Verified]` (checked in source/commands this round),
`[Inference]` (reasoned from evidence), `[Speculation]` (plausible, not
demonstrated), or `[Unverified]` (not confirmable in this round). This
inventory describes code as written; none of it demonstrates exploitability.

## Ranking method

Each surface is scored on four ordinal inputs, each 1–5:

**Score = Reachability × Attacker control × Impact × Control gap**

- **Reachability (R):** how routinely the surface meets attacker input (5 =
  every scan/install of a hostile package; 1 = rare, opt-in, recovery-only).
- **Attacker control (A):** how much of the input a realistic attacker (a
  malicious package author or feed content) shapes (5 = wholly; 1 = marginally).
- **Impact (I):** maximum plausible damage *if the surface's controls failed*
  (5 = attacker code execution/privilege; 1 = cosmetic).
- **Control gap (G):** how much of the surface is *not* covered by demonstrated
  controls or tests (5 = unchecked; 1 = extensively covered and tested).

**Limits of this method — read before using the numbers.** The inputs are
subjective ordinals, not measurements; the product is an ordering device, not a
vulnerability score, a CVSS analogue, or a probability. A single scalar hides
structure (a low-frequency high-impact surface outranks nothing but deserves
review). G scores reflect *demonstrated* coverage only — a passing test suite
raises G credit modestly because tests prove behavior of the tested
configuration, not sufficiency. The ranking must not be used to justify
skipping a lower-ranked surface.

## Summary ranking

| Rank | Surface | R | A | I | G | Score |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | S1 Package control text (PKGBUILD + install hooks) | 5 | 5 | 4 | 2 | 200 |
| 2 | S5 makepkg wrapper handoff | 3 | 4 | 5 | 3 | 180 |
| 3 | S3 Package archives / `.INSTALL` | 4 | 4 | 4 | 2 | 128 |
| 4 | S2 Acquired source (`--deep-static`) | 2 | 5 | 4 | 3 | 120 |
| 5 | S15 Filesystem repository provenance walk | 5 | 5 | 2 | 2 | 100 |
| 6 | S4 Pacman hook mode | 4 | 3 | 4 | 2 | 96 |
| 7 | S12 AI provider response handling | 3 | 5 | 3 | 2 | 90 |
| 8 | S16 npm / editor-task / bytecode metadata | 3 | 5 | 2 | 3 | 90 |
| 9 | S14 Local state, config, credentials | 3 | 3 | 3 | 3 | 81 |
| 10 | S7 Repair Agent command execution | 2 | 4 | 5 | 2 | 80 |
| 11 | S11 MCP server (incl. L1 open candidate) | 2 | 3 | 3 | 4 | 72 |
| 12 | S13 Desktop IPC surface | 2 | 3 | 3 | 3 | 54 |
| 13 | S9 Incident / repository repair (sudo paths) | 2 | 3 | 4 | 2 | 48 |
| 13 | S10 Intelligence updater | 2 | 3 | 4 | 2 | 48 |
| 15 | S8 Recovery repair executor (`arch-chroot`) | 1 | 3 | 5 | 3 | 45 |

---

## S1 — Package control text: PKGBUILD, `source=()`, declared install hooks

- **Entry point / source:** `aurascan/cli.py` (scan entry),
  `aurascan/analyzers/deterministic.py`, `aurascan/core/install_hook.py`
  (`capture`/resolution at `:292-366`, no-follow reads `:1109-1145`),
  `aurascan/makepkg_wrapper.py` (review path).
- **Attacker-controlled input:** every byte of the PKGBUILD, source arrays,
  checksum arrays, `.install` hook text, `.SRCINFO`. [Verified]
- **Security assumptions:** parsing is bounded and literal-only; nothing is
  evaluated; a static match is evidence, never proof of execution.
- **Existing controls:** bounded literal source-array collection (malformed
  arrays, subscripts, namerefs, `source`/`eval`/dynamic mutation fail closed,
  `docs/SECURITY_BOUNDARIES.md:26`); `install=` targets are mandatory evidence
  — missing/unreadable/symlinked/ambiguous hook fails closed and never reuses an
  allow decision (`AGENTS.md` invariants, `install_hook.py:1134-1145`).
  [Verified]
- **Plausible failure modes:** parser gaps (new shell construct misread as
  inert); ambiguity resolved as "safe" instead of coverage; hook path resolved
  through an unexpected symlink component. [Speculation]
- **Maximum plausible impact:** a malicious control flow reaches the consented
  handoff (S5) or installs an unreviewed hook — i.e. delayed execution
  authority, still behind explicit consent. [Inference]
- **Existing tests:** `tests/test_deterministic_rules.py`,
  `tests/test_curated_fixtures.py`, `tests/test_install_hook.py`,
  `tests/test_cli_and_engine.py`, `tests/test_pkgbuild_dependencies.py`,
  `tests/test_makepkg_wrapper.py` (142 tests). [Verified by file presence +
  fresh full-suite run]
- **Missing validation:** nothing demonstrated missing; a systematic
  construct-coverage benchmark (Phase 3) does not exist yet. [Verified — the
  benchmark is NOT EXECUTED this round]
- **Evidence:** `docs/SECURITY_BOUNDARIES.md:20-33`; fresh suite run (README).

## S2 — Acquired source (`--deep-static`)

- **Entry point:** `aurascan/core/source_acquisition.py`
  (`SourcePolicy`/fetchers `:145-168`), `aurascan/analyzers/deep_static.py`.
- **Attacker-controlled input:** upstream archives, VCS checkouts, nested
  archives, checksums, URLs (including redirect targets). [Verified]
- **Assumptions:** acquisition paths are isolated; local sources snapshotted
  no-follow; declared-but-uninspectable sources block.
- **Controls:** `--offline` forbids network; credential/`localhost`/non-public
  IP literals rejected pre- and post-redirect; per-source path isolation;
  bounded entries/bytes; nested archives must be recursively inspected or the
  result blocks (`docs/SECURITY_BOUNDARIES.md:35-47`); git selector identity
  requires a full supported commit (`AGENTS.md`). [Verified for policy
  existence; per-check line coverage [Inference]]
- **Failure modes:** decoder/parser gap in an archive format; DNS rebinding
  (explicitly not eliminated); a bound cache reused before identities bind.
  [Speculation]
- **Max impact:** uninspected attacker bytes feed later execution steps
  (bounded by blocking rules and consent). [Inference]
- **Tests:** `tests/test_source_acquisition.py` (28 of its tests fail under
  this runtime's default PATH and pass under `PATH=/usr/bin:/bin` —
  environment artifact, README), `tests/test_deep_static.py`,
  `tests/test_deep_static_fixtures.py`, `tests/test_git_signature_verification.py`,
  `tests/test_repository_snapshot.py`. [Verified]
- **Missing validation:** no Phase-3 variant benchmark yet. [Verified absence]

## S3 — Package archives and `.INSTALL` capture

- **Entry:** `aurascan/core/package_archive.py`
  (`capture_package_install_hook` `:174`, identity `:58`).
- **Input:** archive members, `.PKGINFO`/`.INSTALL` bytes, member names,
  streamed file the cache presents. [Verified]
- **Assumptions:** the bounded reader's no-follow opens and bsdtar boundary
  hold; official status requires filename + streamed SHA-256 matching the
  root-owned sync DB binding. [Verified (`docs/SECURITY_BOUNDARIES.md:49-77`)]
- **Controls:** `O_NOFOLLOW` opens (`:397-416`), bounded bsdtar runs (`:475`),
  stable regular UTF-8 text required, incomplete capture = coverage finding
  never "no hook"; authentic official archives downgrade only auxiliary checks,
  never deterministic blockers. [Verified]
- **Failure modes:** bsdtar defect on hostile bytes; ambiguous member names
  misread; a cached archive passing identity but carrying undetected malicious
  hook text (detection problem, S1). [Speculation]
- **Max impact:** malicious `.INSTALL` runs as root at install time if
  undetected — the reason this evidence is mandatory. [Inference]
- **Tests:** `tests/test_package_archive.py`, `tests/test_pacman_sync_db.py`,
  `tests/test_official_coverage_policy.py`. [Verified]
- **Missing validation:** nothing demonstrated missing.

## S4 — Pacman hook mode

- **Entry:** `packaging/arch/aurascan.hook` (`Exec = /usr/bin/aurascan`,
  `NeedsTargets`, `AbortOnFail`, `PreTransaction`) → `aurascan/cli.py:606-613`.
- **Input:** package names on stdin; cache archives under
  `/var/cache/pacman/pkg` (user-writable). [Verified]
- **Assumptions:** a bare name must be identity-proven from the archive's own
  metadata before scanning; stale pre-install archives are skipped; unknown
  entries are skipped, not trusted. [Verified (`cli.py:231-302`)]
- **Controls:** `_hook_scan_identity_matches` (`cli.py:231-245`) — "the package
  cache is user-writable, so a same-prefix decoy or a stale corrupted archive
  could otherwise shadow the package pacman is about to install"; explicit-path
  handling rejects cwd shadowing (`:252-262`); blocked scan aborts the
  transaction (`:611-613`). [Verified]
- **Failure modes:** a scanner defect runs in the root transaction context; a
  package passes because its malicious bytes evade S1 rules. [Speculation]
- **Max impact:** root-context defect or undetected malicious package
  installed — mitigated by `AbortOnFail`. [Inference]
- **Tests:** `tests/test_pacman_hook_packaging.py`, `tests/test_pacman_sync_db.py`,
  `tests/test_local_package_db.py`. [Verified]
- **Missing validation:** adversarial cache-swap races are untested (Phase 2).
  [Verified absence]

## S5 — makepkg wrapper handoff

- **Entry:** `aurascan/makepkg_wrapper.py` `run()` (`:257`), handoff `:623-631`.
- **Input:** the checkout (PKGBUILD, hooks, sources), user `makepkg.conf`
  environment, cached sudo state. [Verified]
- **Assumptions:** the reviewed input is the built input; the handoff is
  consented and never silent.
- **Controls:** makepkg identity fixed at `/usr/bin/makepkg` and revalidated
  (`:84,502-513,558-561`); sanitized env + user `makepkg.conf` override
  rejection (`:569-577`); complete input identity recapture immediately before
  the handoff (`:583-591`); `BUILDFILE=` argument pin (`:623-631`, comment
  `:613-617`); `sudo -k` invalidation (`:596-599`, `:172-217`); post-build
  `.INSTALL` byte comparison against the scanned hook (`:633-660`). [Verified]
- **Failure modes:** same-UID replacement of makepkg *after* revalidation —
  acknowledged, not defended (`trusted_executable.py:24-27`); makepkg-internal
  behavior beyond the wrapper's contract (it executes package build logic);
  a checkout mutation racing the recapture window. [Speculation]
- **Max impact:** attacker-chosen build logic runs as the invoking user
  (sudo cache deliberately dropped first). [Verified design; impact [Inference]]
- **Tests:** `tests/test_makepkg_wrapper.py` (142 tests, release evidence;
  included in the fresh 5,714-pass run). [Verified]
- **Missing validation:** the TOCTOU window is untested (needs a race harness,
  Phase 2, disposable VM).

## S6 — Opt-in devtools build sandbox

- **Entry:** `aurascan/core/build_sandbox.py` `build_in_sandbox` (`:361`),
  opt-in via `AURASCAN_AUR_SANDBOX=devtools` / `--aur-sandbox`.
- **Input:** the reviewed checkout; chroot base (trusted infrastructure).
  [Verified]
- **Assumptions:** the base chroot is trustworthy; hash-bound artifacts are the
  installed artifacts.
- **Controls:** fixed captured tools (`:61-66`), private `0700` tree, reduced
  environment, bounded tree/artifacts, in-chroot fixed Bash script
  (`docs/AUR_SANDBOX_DESIGN.md:74-98`), artifact hash + rescan + hook-byte
  comparison before `sudo pacman -U`. [Verified]
- **Failure modes:** shared host kernel escape (explicitly out of scope of the
  guarantee); base modified by root; `.INSTALL` runs as root at install time.
  [Verified documented limits]
- **Max impact:** same as an unsandboxed build but with host filesystem and
  credential exposure reduced. [Inference]
- **Tests:** `tests/test_build_sandbox.py`, `tests/test_runtime_links.py`.
  [Verified]
- **Missing validation:** no kernel-isolation guarantee; a disposable-VM
  backend is listed as remaining work (`docs/AUR_SANDBOX_DESIGN.md:149-156`).

## S7 — Repair Agent command execution

- **Entry:** `aurascan/core/agent.py` (`execute_root_command_request`
  `:2524`, session policy).
- **Input:** AI-proposed command strings; incident/upgrade evidence; access
  requests. [Verified]
- **Assumptions:** the allowlist enumerates every executable form; a fresh
  confirmation binds the exact command.
- **Controls:** fail-closed segment allowlist (builtins `:385`, read-only
  diagnostics `:394`, constrained pacman `:342`; validation `:1571-1600`);
  fresh just-in-time confirmation per exact command; SHA-256 `plan_hash`
  constant-time binding (`:2573-2576`); `user-shell` cannot run root commands
  (`:1709-1711`); privileged helper identity captured/revalidated
  (`:2665-2705`). [Verified]
- **Failure modes:** a parser gap in command segmentation (e.g. quoting/
  expansion slips); a validated diagnostic that mutates despite its contract;
  user habituation to confirmations. [Speculation]
- **Max impact:** allowlisted-but-surprising command execution as user or root
  — deliberately bounded, "not unrestricted execution"
  (`docs/SECURITY_BOUNDARIES.md:164-173`). [Inference]
- **Tests:** `tests/test_agent.py`, `tests/test_agent_config.py`. [Verified]
- **Missing validation:** adversarial command-grammar corpus (Phase 5/2) not
  run this round.

## S8 — Recovery repair executor (`arch-chroot`)

- **Entry:** `aurascan/core/recovery_repairs.py` `execute_recovery_plan`
  (`:881`), recipes `:458-845`.
- **Input:** target filesystem state, target tools, Snapper metadata, journal
  text, recovery metadata. [Verified]
- **Assumptions:** target tools validated before use; journal evidence is
  systemd-produced; typed confirmations are unforgeable.
- **Controls:** `_trusted_target_binary`/`_trusted_arch_chroot_tools`
  (`:100-128`) with explicit refusals (`:572,:604,:809`); typed confirmation
  phrase per action (`:884-918`); journal accepted only from
  `_COMM=systemd _PID=1` (`:383`); snapshot actions root-owned metadata only.
  [Verified]
- **Failure modes:** target-side hooks/config execute as recovery root; a
  compromised target manipulates state the queries read; chroot is not a
  containment boundary for UID 0. [Verified documented limits]
- **Max impact:** root actions on a target the user believes is recoverable —
  mitigated but not contained. [Inference]
- **Tests:** `tests/test_recovery.py` (1 test environment-fragile: USB dry-run
  needs PATH-resolvable `lsblk`, README), `tests/test_recovery_repairs`-family
  coverage inside `test_recovery.py` [Unverified — exact sub-coverage not
  enumerated], `tests/test_recovery_artifact_auditor.py`,
  `tests/test_recovery_network.py`, `tests/test_recovery_boot.py`. [Verified
  file presence]
- **Missing validation:** manipulated-recovery-metadata chains (charter Phase
  4 chain C) not executed.

## S9 — Incident / repository repair sudo paths

- **Entry:** `core/incident_repairs.py` (`apply_repair_plan` `:474`,
  `execute_repair_request` `:526`), `core/repository_repair.py` (`:50`).
- **Input:** host state, diagnostic output, mirror configuration. [Verified]
- **Assumptions:** the repair catalog is complete; request files are validated.
- **Controls:** root checks (`incident_repairs.py:497,:718`); command catalog
  (`:432`); run backup + manifest before privileged writes
  (`repository_repair.py:4-13`); captured `sudo` identity via
  `run_trusted_command`. [Verified]
- **Failure modes:** a crafted diagnostic output steering planning; restore
  targets swapped between plan and execution. [Speculation]
- **Max impact:** privileged config writes under `/etc`/`/var`. [Inference]
- **Tests:** `tests/test_incident_repairs.py`, `tests/test_incidents.py`,
  `tests/test_incident_automation.py`, `tests/test_upgrade_preflight.py`.
  [Verified]
- **Missing validation:** replay/stale-approval tests (Phase 2 category B) not
  executed.

## S10 — Intelligence updater

- **Entry:** `core/intelligence_transport.py` (`_download` `:112`),
  `core/intelligence_cli.py` (`_require_root` `:129`), store/crypto modules.
- **Input:** downloaded feed bytes, redirect targets, mirror metadata, tray
  status. [Verified]
- **Assumptions:** packaged fingerprints and bounded GnuPG are trustworthy;
  one snapshot per operation.
- **Controls:** redirects refused (`:62-106`); bounded size/deadline
  (`:112-149`); TLS default verification (`:116-117`); unprivileged download
  separated from network-isolated privileged verification; rollback, unsupported
  schema, expired activation, changed same-sequence content rejected
  (`docs/SECURITY_BOUNDARIES.md:195-204`). [Verified]
- **Failure modes:** GnuPG/parser defect; fingerprint packaging compromised at
  a level above this boundary; sequence-reset attacks if state is lost.
  [Speculation]
- **Max impact:** attacker-controlled detection data (integrity, not code
  execution — no record grants execution authority, `AGENTS.md`). [Inference]
- **Tests:** `tests/test_intelligence_*` (10 files), `tests/test_trust_diff.py`.
  [Verified]
- **Missing validation:** no live feed adversarial testing (prohibited this
  round).

## S11 — MCP server (includes the L1 open candidate)

- **Entry:** `aurascan/mcp/server.py` (`run_server` `:90`),
  `aurascan/mcp/guards.py`, `mcp/tools/*`.
- **Input:** JSON-RPC method/arguments from the MCP host (tool arguments
  include paths and content). [Verified]
- **Assumptions:** the configured roots bound every read; guard order is
  load-bearing.
- **Controls:** containment/regular-file/size guards (`guards.py:26-49`), size
  cap + growth check (`:61-75`), redaction (`mcp/redaction.py`), empty write
  surface; two annotated bounded subprocess call sites. [Verified]
- **L1 open candidate [Verified code description, [Unverified] exploitability]:**
  `read_capped` opens the resolved path without `O_NOFOLLOW` (`:64`) and never
  re-decides root containment on the descriptor; a symlink swapped between
  `resolve_regular_file` and the open reads outside the root. Not a confirmed
  exploit — needs a writable directory component + a race; treated as a Phase 2
  candidate.
- **Failure modes (beyond L1):** tool-argument confusion; redaction gaps.
  [Speculation]
- **Max impact:** same-UID-readable bytes leave containment into an MCP
  response (information disclosure). [Inference]
- **Tests:** `tests/test_mcp_path_guards.py`, `test_mcp_no_io.py`,
  `test_mcp_tools.py`, `test_mcp_schemas.py`, `test_mcp_redaction.py`,
  `test_mcp_protocol.py`, `test_mcp_architecture.py`, `test_mcp_evidence.py`,
  `test_mcp_online.py`. [Verified]
- **Missing validation:** a race test reproducing L1 (Phase 2); no such test
  exists. [Verified absence]

## S12 — AI provider response handling

- **Entry:** `core/ai_provider.py` (`call_ai_provider` `:544`),
  `analyzers/ai_static.py` (validator `:150-180`), `core/finding_explainer.py`
  (`:155-179`), `core/instruction_guard.py` AI (`:5451-5506`),
  `core/aur_update_review.py`.
- **Input:** full model responses; untrusted artifact text embedded in prompts.
  [Verified]
- **Assumptions:** the validators' schema/ID allowlists are complete; accepted
  prose stays untrusted.
- **Controls:** duplicate-key-rejecting strict JSON; allowlisted behavior
  families; line refs restricted to sent lines; raise-only (`ai_static.py:123`,
  `instruction_guard.py:5330`); redirects refused (`ai_provider.py:163-164`);
  loopback-only local providers (`:234-271`); response cap 1 MiB (`:144`);
  rejected output never persisted; no tools/URL/command authority in prompts.
  [Verified]
- **Failure modes:** prompt injection influencing *displayed* advisory prose
  (accepted prose is untrusted interpretation); an unknown schema corner
  accepted; evidence-laundering chains across AI stages (Phase 5 territory).
  [Speculation]
- **Max impact:** raised severity on an existing finding or misleading prose —
  deterministic results cannot be lowered; the agent path is gated by S7.
  [Verified]
- **Tests:** `tests/test_ai_provider.py`, `tests/test_dustmaker_ai_boundary.py`,
  `tests/test_finding_explainer.py`, `tests/test_injection_*` (13 files),
  `tests/test_instruction_guard*.py`. [Verified]
- **Missing validation:** end-to-end injection benchmark (Phase 5) not run.

## S13 — Desktop IPC surface

- **Entry:** `desktop/electron/preload.cjs:12-30` (13 channels) →
  `main.cjs:342-372` handlers → `argv.cjs:178-265`.
- **Input:** renderer messages: action IDs, provider/credential, AI config
  values, `file_id`/`report_id`/`sha256` strings. [Verified]
- **Assumptions:** the closed action catalog and shape regexes are complete;
  the renderer is compromised-adversarial by design.
- **Controls:** fixed argv from constants; only `/usr/bin/aurascan` spawned;
  validPath/regex gates (`argv.cjs:29-31,168-176`); secret on stdin only; env
  allowlist; 8 MiB output cap +
  timeouts; stderr dropped; navigation/popups/webviews denied
  (`main.cjs:285-287,299-305`); CLI-side `--expect-report-id`/`--expect-sha256`
  revalidation (`argv.cjs:225-235`). [Verified]
- **Failure modes:** renderer-asserted confirmation for `instruction_disable`
  (`argv.cjs:237` — `--yes` is added on the renderer's word); a future
  handler added without the argv discipline; misdisplay inducing user consent.
  [Verified structure; impact [Speculation]]
- **Max impact:** state changes within the fixed catalog (approve/disable an
  instruction file bound to a real report; AI key storage; incident resolve)
  without genuine user consent — never arbitrary execution or install.
  [Inference]
- **Tests:** `desktop/` vitest suites (`desktop/src`, `desktop/vitest.config.ts`)
  and `tests/test_ui_actions.py`, `test_ui_contract.py`, `test_ui_report.py`,
  `test_ui_settings.py`, `tests/test_updater_tray_desktop.py`. Desktop vitest
  run `NOT EXECUTED` this round. [Verified paths; run state [Verified absent]]
- **Missing validation:** adversarial IPC fuzzing of the 13 channels; the
  consent-forgery path on `instruction_disable`.

## S14 — Local state, config, credentials

- **Entry:** `core/config.py`, `core/state_file.py`, `core/cache.py`,
  `settings` CLI (`docs/SECURITY_BOUNDARIES.md:271-296`).
- **Input:** config file contents, restored backups, prior reports, a typed
  credential. [Verified]
- **Assumptions:** owner/mode checks and the private lock hold; approvals are
  machine-and-UID bound.
- **Controls:** atomic writes with explicit mode; secret-free serializers
  (presence booleans); credential on stdin, `0600` in `0700`; interrupted
  transactions fail closed. [Verified]
- **Failure modes:** same-UID malware attacking state/config (acknowledged
  limit, `docs/SECURITY_BOUNDARIES.md:10-13`); stale approval reuse after
  state loss. [Speculation]
- **Max impact:** forged local state changes trust displays; stolen credential
  file (filesystem confidentiality). [Inference]
- **Tests:** `tests/test_ui_settings.py`, `tests/test_config_drift.py`,
  `tests/test_clamav_and_cache.py`, `tests/test_instruction_guard_enrollment.py`.
  [Verified]
- **Missing validation:** hostile-backup restoration chains.

## S15 — Filesystem repository provenance walk

- **Entry:** `core/repository_provenance.py` (bounded walk),
  `analyzers/repository_provenance.py` (correlations).
- **Input:** every file beside the PKGBUILD; symlinks; archives; executables.
  [Verified]
- **Assumptions:** the walk is complete; link handling is one-hop in-checkout
  only.
- **Controls:** always-on, local, no-follow, no Git/native tools; prunes VCS
  internals/caches/generated trees; executable/archive magic classification;
  presence MEDIUM / install HIGH / execution-or-SUID CRITICAL
  (`docs/SECURITY_BOUNDARIES.md:206-215`). [Verified]
- **Failure modes:** traversal gap reported as clean instead of coverage;
  carrier-classification bypass. [Speculation]
- **Max impact:** a presence/correlation finding missed (under-reporting), not
  execution. [Inference]
- **Tests:** `tests/test_repository_provenance_analyzer.py`,
  `tests/test_repository_snapshot.py`, `tests/test_curated_fixtures.py`.
  [Verified]
- **Missing validation:** systematic carrier-variant corpus (Phase 3).

## S16 — npm / editor-task / precompiled-bytecode metadata

- **Entry:** `analyzers/npm_*.py`, `analyzers/editor_tasks.py`,
  `analyzers/python_bytecode.py`, `analyzers/python_bytecode_execution.py`.
- **Input:** manifests, lockfiles, task configs, `.pyc` headers. [Verified]
- **Assumptions:** structural parsing only; no package manager is ever run.
- **Controls:** bounded no-follow data reads; traversal needs concrete
  path-escape components; bytecode is opaque (magic/header bytes only, never
  imported/decompiled); campaign intelligence offline and source-attributed
  (`AGENTS.md`). [Verified]
- **Failure modes:** parser gap; over-broad correlation (false positives);
  registry-state confusion. [Speculation]
- **Max impact:** missed or spurious findings; installed-version exposure
  claims must stay uncertainty-aware. [Inference]
- **Tests:** `tests/test_npm_*` (6 files), `tests/test_editor_tasks.py`,
  `tests/test_editor_task_integration.py`, `tests/test_python_bytecode.py`,
  `tests/test_pnpm_buildchain.py`, `tests/test_vendor_emergency_advisories.py`.
  [Verified]
- **Missing validation:** none demonstrated beyond the absent Phase 3 corpus.

---

## Open assumptions — ranked targets for later Red tests

Assumptions, **not** vulnerabilities. Each names what a controlled test would
need to demonstrate to convert it into a finding (or retire it).

1. **A1 — Post-revalidation tool swap (TOCTOU).** The trusted-executable model
   explicitly cannot prevent same-UID replacement between revalidation and
   exec (`trusted_executable.py:24-27`) [Verified statement]. Test: race a
   replacement against the makepkg handoff in a disposable VM; measure whether
   the recapture window (`makepkg_wrapper.py:583-591`) narrows it enough.
2. **A2 — L1 MCP guard symlink swap.** `mcp/guards.read_capped` containment
   gap (S11) [Verified code behavior]. Test: swap a symlink between
   `resolve_regular_file` and `read_capped` against a live MCP server.
3. **A3 — Cache-archive identity race (hook mode).** Identity is proven from
   archive metadata (`cli.py:231-245`) but the cache stays user-writable
   [Verified]. Test: swap an identity-matching decoy after the check and before
   pacman installs the real name.
4. **A4 — Consent forgery from the desktop renderer.** `instruction_disable`
   trusts the renderer's asserted confirmation (`argv.cjs:237`)
   [Verified]. Test: compromised-renderer scenario driving all 13 channels;
   enumerate which state changes a renderer can cause without a real user
   click.
5. **A5 — Base-chroot integrity.** AuraScan verifies the chroot shape but "it
   does not prove the base was never modified by root"
   (`docs/AUR_SANDBOX_DESIGN.md:63-65`) [Verified]. Test: whether any
   observable evidence can distinguish a tampered base (probably not —
   document as an accepted limit if not).
6. **A6 — Recovery target-side hook execution.** Intact target tools still run
   the target's own hooks as recovery root (`docs/SECURITY_BOUNDARIES.md:184-193`)
   [Verified]. Test: compromised-target fixture (chain C) for observable
   differences between "clean repair" and "target compromised".
7. **A7 — Command-grammar completeness of the Repair Agent allowlist.**
   Allowlists validated (`agent.py:1571-1600`) but segment grammar is complex
   [Inference]. Test: adversarial command corpus (quoting, expansion, unicode)
   asserting refusal.
8. **A8 — Advisory-prose laundering.** Accepted AI prose is untrusted but
   *displayed to humans* near findings [Verified framing]. Test: injection
   corpus measuring whether laundered prose can shift a human decision without
   touching any deterministic field (Phase 5).
9. **A9 — DNS rebinding vs lexical URL checks.** Explicitly not eliminated
   (`docs/SECURITY_BOUNDARIES.md:46-47`) [Verified]. Test only in a disposable
   network namespace; low priority because `--deep-static` is opt-in and
   offline mode forbids transport.
10. **A10 — Intelligence feed trust chain.** Relies on packaged fingerprints +
    bounded GnuPG [Verified]; test rollback/schema attacks through the public
    interface only.

## Evidence references

- Commands run this round (all read-only): `rg`/`sed`/`git` inspections;
  `python tools/architecture_audit.py --strict` (exit 0; 135 modules, 87,315
  lines); `python tools/architecture_audit.py --format json` (exit 0);
  `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q` (exit 0; 5,714 passed,
  3 skipped); default-PATH `pytest -q` (exit 1; 33 failed/5,681 passed/
  3 skipped — environment artifacts, see README); targeted single-test runs
  reproducing and clearing the PATH artifact (2 passed under sanitized PATH).
- Source anchors appear inline per surface.
