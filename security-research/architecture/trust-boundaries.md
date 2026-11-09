# AuraScan trust boundaries — source-grounded model

Baseline: `02ac13d`, AuraScan 0.15.0, rule catalogue 1.15.0. Diagram:
[`trust-boundaries.mmd`](trust-boundaries.mmd). Claims are labelled
`[Verified]` (checked in source this round), `[Inference]`, `[Speculation]`,
`[Unverified]`. Line numbers refer to this baseline; drift invalidates them.

Two standing statements (from `docs/SECURITY_BOUNDARIES.md:8-16`, consistent
with source): **a boundary is risk reduction, not a sandbox**, and **a passing
test does not make a boundary safe**.

## Model in one paragraph

Untrusted bytes — PKGBUILD text, declared install hooks, acquired source,
package archives, agent instruction files, npm metadata, host state — enter
through bounded, no-follow capture stages and are analyzed by deterministic
static analyzers that execute nothing (`tools/architecture_audit.py` INV-001,
`docs/ARCHITECTURE.md:316`). Deterministic policy (engine, risk, rule catalog)
decides severity, blocking and review. AI is separately opt-in, advisory and
raise-only; a strict validator sits between model bytes and any persisted
field. Execution authority lives in a small set of adapter/workflow modules
that invoke fixed, root-owned, revalidated system tools through injected
runners, plus four deliberate handoffs (makepkg build, opt-in devtools build,
sudo/pacman upgrade/repair, arch-chroot recovery). The desktop renderer and the
MCP read-only tools aggregate and display evidence; they cannot execute,
install or change a deterministic result. Consent gates (review acceptance,
sudo password, typed confirmation phrases, fresh per-command confirmation)
bound every privileged transition.

## Boundary inventory

| # | Boundary | Untrusted side | Trusted side | Control (source) | Nature |
| --- | --- | --- | --- | --- | --- |
| B1 | Package control text | PKGBUILD, `source=()`, `.install` hooks, `.SRCINFO` | Deterministic policy, rule catalog | Bounded literal-only parse; malformed/dynamic forms fail closed (`aurascan/core/install_hook.py:1109-1145`, `aurascan/analyzers/deterministic.py`) | Risk reduction |
| B2 | Acquired source (`--deep-static`) | Downloaded archives, upstream trees, nested archives | Acquisition snapshot identity, policy | Path-isolated bounded capture; `--offline` forbids network (`aurascan/core/source_acquisition.py:145-168`) | Risk reduction |
| B3 | Package archives | `.PKGINFO`/`.INSTALL` members | Bounded archive reader | No-follow `O_NOFOLLOW` opens (`aurascan/core/package_archive.py:397-416`), bounded bsdtar (`:475`), stable UTF-8 text required (`:174-215`) | Risk reduction |
| B4 | Pacman hook mode | Cache archives, package names on stdin | The scan itself (runs under pacman, `AbortOnFail`) | Identity proof per archive before scan (`aurascan/cli.py:231-245`); bare names resolved against cache, not cwd (`:252`) | Risk reduction |
| B5 | Filesystem repository provenance | Files beside the PKGBUILD | Bounded no-follow walk | Always-on local walk, no Git/native tools; links read not followed (`docs/SECURITY_BOUNDARIES.md:206-215`) | Risk reduction |
| B6 | Agent instruction files | `AGENTS.md`, `SKILL.md`, Cursor/MCP configs, CodeWhale TOML | Instruction Guard discovery/manifests | Bounded `O_NOFOLLOW` reads (`aurascan/core/instruction_guard.py:1008,1109,1211,1400,2085,2326,2570`); AI sees opaque IDs only (`:5330,5451`) | Risk reduction |
| B7 | Model input/output | Provider responses; artifact text embedded in prompts | Deterministic findings, strict schema, consent | Duplicate-key-rejecting strict JSON, allowlisted fields (`aurascan/analyzers/ai_static.py:141-180`); redirects refused (`aurascan/core/ai_provider.py:163-164`); local loopback-only (`:234-271`) | Risk reduction |
| B8 | Native tools over hostile data | Bytes handed to `git`/`gpg`/`bsdtar`/`clamscan`/`makepkg`/helpers | Fixed root-owned tool identities | Capture + revalidate-before-use (`aurascan/core/trusted_tools.py:69-113`, `trusted_executable.py:100-137`), bounded output 256 KiB (`trusted_tools.py:15`) | Risk reduction (explicitly not a sandbox: `trusted_executable.py:24-27`) |
| B9 | makepkg wrapper handoff | The reviewed checkout | Wrapper policy + consent | Revalidation + input recapture + sudo invalidation immediately before build (`aurascan/makepkg_wrapper.py:558-599`), post-build `.INSTALL` byte comparison (`:633-660`) | Deliberate consented handoff — **executes package build logic** |
| B10 | Devtools build sandbox | Reviewed checkout | devtools chroot boundary | Explicit opt-in (`aurascan/core/build_sandbox.py:361`), fixed tools (`:61-66`), hash-bound rescanned artifacts (`docs/AUR_SANDBOX_DESIGN.md:24-52`) | Risk reduction (shared host kernel; `docs/AUR_SANDBOX_DESIGN.md:54-72`) |
| B11 | Privileged repair/recovery | Host state, diagnostic output, target filesystem | Repair catalog, typed consent, trusted sudo/pacman | Fresh just-in-time confirmation; allowlisted commands (`aurascan/core/agent.py:342-394,1571-1600`); typed confirmations (`aurascan/core/recovery_repairs.py:881-918`); target tool validation (`:100-128`) | Risk reduction (a chroot is not a boundary for UID 0: `docs/SECURITY_BOUNDARIES.md:184-193`) |
| B12 | Intelligence updates | Feed bytes, mirror metadata | Packaged fingerprints, GnuPG, atomic install | Unprivileged download separate from privileged verify (`aurascan/core/intelligence_transport.py:56-149`, `intelligence_cli.py:129-131`); redirects refused | Risk reduction |
| B13 | Local state & config | Config contents, restored backups, prior reports | Ownership/mode checks, private lock | Atomic bounded writes (`core/state_file.py`), machine-and-UID-bound approvals (`docs/SECURITY_BOUNDARIES.md:217-226`) | Risk reduction |
| B14 | Desktop renderer | Compromised renderer | Main-process action catalog | Sandboxed renderer (`desktop/electron/main.cjs:299-305`), fixed action IDs → fixed argv (`desktop/electron/argv.cjs:178-265`), navigation/popups/webviews denied (`main.cjs:285-287`) | Pure view; main revalidates |
| B15 | MCP server | MCP client requests | Read-only stdio JSON-RPC tools | Guarded reads (`aurascan/mcp/guards.py:26-75`), empty write surface, bounded subprocess in two annotated tools (`aurascan/mcp/tools/security_audit.py:34-38`) | Risk reduction; **L1 open candidate below** |

## Question 1 — Boundary analysis

### Components that hold execution authority (can execute code or change the system)

[Verified by source, cross-checked against `tools/architecture_audit.py --strict`
exit 0, which reports 6 direct `process` call sites: `core/agent.py`,
`core/local_package_db.py`, `core/package_archive.py`, `core/trusted_tools.py`,
`mcp/tools/security_audit.py`, `mcp/tools/security_audit_online.py`.]

- **`aurascan/makepkg_wrapper.py`** — hands the build to `makepkg`
  (`:623-631`), which executes package build logic as the invoking user.
- **`aurascan/core/build_sandbox.py`** — `build_in_sandbox` (`:361`) runs
  `arch-nspawn`/chroot builds and `sudo pacman -U`; also `sudo rm -rf` cleanup
  (`:562-596`).
- **`aurascan/core/upgrade_preflight.py`** — the `sudo`/`pacman` upgrade
  handoff and all upgrade-driven pacman queries pinned to the trusted identity
  (`:162-194`).
- **`aurascan/core/incident_repairs.py`** — repair execution through a sudo
  helper with root checks (`:474-526`, `:718`).
- **`aurascan/core/repository_repair.py`** — privileged mirrorlist restore
  through a captured `sudo` identity (`:50-62`).
- **`aurascan/core/recovery_repairs.py`** — executes target programs as
  recovery root via `arch-chroot` (e.g. `:577`, `:613`, `:647`, `:684`, `:770`).
- **`aurascan/core/recovery_boot.py`** — subprocess-based boot-image tooling
  (e.g. `sign_recovery_image`, `:428`).
- **`aurascan/core/agent.py`** — the Repair Agent executes allowlisted
  commands through a validated privileged helper (`:2524-2576`, `:2665-2705`).
- **`aurascan/core/intelligence_cli.py`** — privileged verify/install path
  (`:129-131` root requirement).
- **`aurascan/mcp/tools/security_audit.py` / `security_audit_online.py`** — one
  injected `subprocess.run` each (`security_audit.py:34-38`).
- **Pacman hook mode** (`aurascan/cli.py:606-613`, `packaging/arch/aurascan.hook`)
  — the scanner itself runs inside the pacman transaction (`Exec =
  /usr/bin/aurascan`, `AbortOnFail`, `PreTransaction`) [Verified hook file;
  that alpm runs hooks with pacman's privileges, i.e. root, is [Inference]].

All other execution flows through `core/trusted_tools.py` /
`core/bounded_process.py` with injected runners; the audit's process count
deliberately tracks *direct* call sites and under-reports injected-runner
authority (`docs/ARCHITECTURE.md:205-212`) — this model treats injected-runner
callers as execution-authoritative too.

### Components that only render or aggregate evidence

[Verified] The six presenter modules (`docs/ARCHITECTURE.md:127-136`,
INV-016: no process/network/write/privilege/AI), `core/ui_cli.py` (read-only
snapshot composition, `aurascan-ui/1` contract, `:27`), `core/ui_actions.py`
(fixed catalog; install/downgrade are `terminal_only`, `:134,:149`),
`core/finding_explainer.py` (display-only, `:5`), the Electron renderer and
preload (`desktop/electron/preload.cjs:12-30`), and the MCP read-only tools
`scan_content` / `scan_path` / `audit_agent_config` (data reads through the
guards). These can misdisplay evidence; they cannot change a deterministic
result, install anything, or establish trust.

### Doc claims not supported by current source

[Verified mismatches — the maintained documents are maps; these three are
stale or wrong at this baseline:]

1. `docs/ARCHITECTURE.md:65` — "Current measurement: **131 modules, 85,081
   physical lines**". The audit at `02ac13d` reports **135 modules, 87,315
   lines** (`python tools/architecture_audit.py --strict`, exit 0, 2026-11-09).
   The layer table at `docs/ARCHITECTURE.md:67-79` is stale in the same way
   (e.g. `analysis` 19→32, `application` 27→39, `mcp` 14→17,
   `presentation` 16→17 per the audit).
2. `docs/ARCHITECTURE.md:198` — "Process execution | 5" modules. The audit
   reports **6**; the listed five plus `mcp/tools/security_audit_online.py`,
   which the table omits (its wrapper body holds a real `subprocess.run` at
   `security_audit_online.py:119-121`).
3. `docs/SECURITY_BOUNDARIES.md:265-266` — the Electron shell "exposes exactly
   four preload operations: refresh, open a report through a native dialog,
   read settings, and store one AI credential". `desktop/electron/preload.cjs:12-30`
   exposes **13** operations (the four named plus `configureAi`,
   `reviewInstructions`, `scanInstructions`, `approveInstruction`,
   `disableInstruction`, `scanIncidents`, `resolveIncidents`, `openUpgrade`,
   `npmAudit`). The *security* claim behind the sentence — fixed action IDs,
   no renderer-supplied executables or command strings — is still supported by
   `desktop/electron/argv.cjs:124-138,178-265`; the count is wrong.

No other maintained-document claim checked this round contradicted source;
claims outside the files read are `[Unverified]`.

## Question 2 — Privilege transitions

Each transition names what is revalidated immediately before the crossing and
what is not. "Not revalidated" is a statement about source, not a finding.

| Transition | Where | Revalidated immediately before | Not revalidated / residual |
| --- | --- | --- | --- |
| T1: scan → `makepkg` build (package code executes) | `makepkg_wrapper.py:558-631` | makepkg tool identity (`:558-561`); user `makepkg.conf` override rejection (`:569-577`); complete input identity recapture — PKGBUILD + declared hook + repository snapshot (`:583-591`, comment "Re-capture the complete input identity as the final package-state operation before the handoff"); `sudo -k` invalidation (`:596-599`, `:172-217`) | Nothing re-checks the makepkg identity between `:558` and exec at `:623`; same-UID replacement after revalidation is an acknowledged limit (`trusted_executable.py:24-27`) [Verified docstring]. Post-build `.INSTALL` bytes are compared to the scanned hook (`:633-660`) [Verified] |
| T2: upgrade → `sudo pacman` transaction | `upgrade_preflight.py:162-194`, `trusted_executable.py:137` | `run_trusted_command` revalidates the captured `pacman`/`sudo` identity before each call; every downstream collector's pacman argv is bound to that identity (`upgrade_preflight.py:186-194`) | AUR helper build routing is *not* under the wrapper — that is exactly the `UPG-AUR-BUILD-UNSCANNED` CRITICAL blocker (`docs/AUR_SANDBOX_DESIGN.md:9-18`) [Verified] |
| T3: sandbox → chroot build + `sudo pacman -U` | `build_sandbox.py:361-519` | Fixed tools captured/revalidated (`:61-66`, `:441-461`); chroot base path root-owned + marker checked (`:304-325`); artifacts hash-bound and rescanned before install (`docs/AUR_SANDBOX_DESIGN.md:24-52`) | Base-chroot history cannot be proven (`docs/AUR_SANDBOX_DESIGN.md:63-65`); chroot shares the host kernel (`:58-59`) [Verified doc, consistent with code] |
| T4: recovery → `arch-chroot` as recovery root | `recovery_repairs.py:846-918` | Target-resolved tools validated root-owned/non-symlink (`:100-128`, refusal messages `:572,:604,:809`); typed confirmation phrase per action (`:884-918`); journal evidence only from `_COMM=systemd _PID=1` (`:383`) | Target hooks/configuration still run as root inside the chroot; package-state queries are target-derived; a compromised target stays untrusted (`docs/SECURITY_BOUNDARIES.md:184-193`) [Verified] |
| T5: incident repair → sudo helper | `incident_repairs.py:474-526,718` | `geteuid()` gates (`:497`, `:718`); request-file validation in `execute_repair_request` (`:526`); commands limited to `trusted_repair_commands` catalog (`:432`) | Diagnostic output is untrusted input to later stages [Inference] |
| T6: repository repair → sudo | `repository_repair.py:50-62` | Captured `sudo` identity via `run_trusted_command`; run backup + manifest first | Backup/restore correctness is tested but is a restore of user-visible config [Inference] |
| T7: intelligence verify/install → root | `intelligence_cli.py:129-131` | `_require_root`; download is unprivileged and physically separate (`intelligence_transport.py:56-149`); redirects refused (`:62-106`); TLS default verification (`:116-117`) | Feed trust rests on packaged fingerprints + bounded GnuPG; provenance of the packaged fingerprint itself is packaging-level [Inference] |
| T8: pacman hook mode | `cli.py:606-613` | Archive identity must be *proven* from the archive's own metadata before scanning (`cli.py:231-245` — the cache is user-writable, so a name match is insufficient); stale pre-install archives skipped (`:280-302`) | The scan runs inside the pacman transaction as root; a scanner defect is a root-context defect [Inference] |

## Question 3 — AI authority

**Where model input or output can influence a decision.** [Verified]

1. **Package AI (`analyzers/ai_static.py`)** — may raise severity / add
   advisory findings on already-captured evidence. The prompt is explicitly
   "raise-only" (`:123`); output passes a strict duplicate-key-rejecting JSON
   validator with allowlisted behavior families and line references restricted
   to included lines (`:141-180`). A protocol failure produces a coverage-style
   finding and retains no raw model prose (`:186-199`).
2. **Instruction Guard AI (`core/instruction_guard.py`)** — advisory only,
   `raise_only: True` enforced on stored output (`:5330,:5451,:5480`); input is
   bounded opaque evidence IDs and fixed reasons; it "may raise but never lower
   deterministic severity" (`:5146`).
3. **Upgrade advisory / AUR update review** — advisory; "can never lower a
   deterministic result" (`core/aur_update_review.py:30`).
4. **Finding explanation (`core/finding_explainer.py`)** — display-only: sends
   at most six fixed user-facing facts (`:47`), "never adds or removes
   findings, never lowers" (`:5`), and cannot appear in JSON output
   (`docs/SECURITY_BOUNDARIES.md:107-116`).
5. **Repair Agent AI (`core/agent.py`)** — the model *proposes* commands; it
   never executes one.

**The deterministic gate between AI and execution.** [Verified]

- For 1–4: the strict response validators (`ai_static.py:150-180`,
  `finding_explainer.py:155-179`, `instruction_guard.py:5451-5506`) accept only
  exact schemas and known IDs; rejected output is discarded, never persisted.
  AI can only *raise*; deterministic findings, blockers and trust states are
  computed without any AI module (INV-006: domain/risk/catalog must not depend
  on AI providers).
- For 5: the gate is `_validate_agent_command_policy`
  (`agent.py:1600`, with the allowlists at `:342-394`) plus a **fresh
  just-in-time user confirmation for each exact command**; the approved command
  is bound to a SHA-256 `plan_hash` and compared in constant time before
  execution (`agent.py:2573-2576`). `user-shell` cannot accept root commands
  (`:1709-1711`).

**Display-only vs. security decision.** Display-only: finding explanation,
presenters, `aurascan ui` snapshot, tray text. Security-relevant but
raise-only: package AI severity raises, Instruction Guard AI rationale.
Security decisions — severity, blocking, review requirement, install/handoff
eligibility — are made exclusively by deterministic policy
(`core/engine.py`, `core/risk.py`, `core/rule_metadata.py`).

## Question 4 — Desktop boundary

[Verified from IPC handlers in `desktop/electron/main.cjs` and the argv builder
`desktop/electron/argv.cjs`, not from UI text.]

**What a compromised renderer can request** — exactly the 13 channels in
`preload.cjs:12-30`: snapshot refresh, open-report (native dialog), read
settings, store AI key (provider+secret), configure AI (non-secret values),
instruction review/scan/approve/disable, incident scan/resolve, open upgrade
terminal, npm audit.

**What the main process refuses** [Verified]:

- Any action not in the fixed catalog: `actionArgv` returns `null` and the
  request fails as "Unsupported desktop action" (`main.cjs:101-105`,
  `argv.cjs:178-265`). The catalog is closed: 5 read-only + 7 mutating action
  IDs (`argv.cjs:124-138`).
- Executables, flags, or command strings — argv vectors are built in the main
  process from constants; only `/usr/bin/aurascan` is spawned
  (`argv.cjs:19,157-166`; dev override must be absolute and control-char-free).
- Paths that are not absolute, contain control characters, or start with `-`
  (`argv.cjs:168-176`); report and project directories are chosen by native
  dialogs in the main process (`main.cjs:211-223,372-381`).
- Secrets in argv/environment: the AI credential travels once on the child's
  stdin (`main.cjs:120-140`); the forwarded environment allowlist excludes all
  `AURASCAN_AI_*`/credential variables (`argv.cjs:110-118`).
- Unbounded behavior: 8 MiB stdout cap (`argv.cjs:20`), per-action timeouts
  with SIGKILL (`main.cjs:62-67`), stderr drained and never forwarded
  (`main.cjs:81`).
- Navigation, popups, webviews, Node integration (`main.cjs:285-287,299-305`).
- Unbound instruction actions: approve/disable require well-formed
  `file_id`/`report_id`/`sha256` (`argv.cjs:29-31,211-238`) and pass
  `--expect-report-id`/`--expect-sha256` so the CLI revalidates the exact
  report binding.

**Residual, honestly stated.** [Verified structure, [Speculation] impact] The
renderer's own confirmation is what adds `--yes` to `instruction_disable`
(`argv.cjs:237`): a compromised renderer can suppress its dialog and
assert confirmation. The deterministic backstop is the CLI's report-ID/SHA-256
binding — the action still cannot touch a file whose report the user never saw
— but the *human* consent moment can be forged, so a renderer compromise is
not purely display-layer: it can drive state-changing actions within the fixed
catalog. Install/downgrade actions remain terminal-only (`ui_actions.py:134,149`).

## Open candidate: `mcp/guards.read_capped` (L1)

Recorded at `docs/ARCHITECTURE.md:222`; the code matches the record. [Verified]

- `resolve_regular_file` decides containment on `os.path.realpath` and
  `os.stat` (`aurascan/mcp/guards.py:26-49`).
- `read_capped` then opens the *resolved path* with `O_RDONLY|O_NONBLOCK` and
  **without `O_NOFOLLOW`** (`guards.py:61-64`), re-deciding only file type and
  size on the descriptor (`:67-72`) — never root containment.
- A symlink swapped in between resolution and open is therefore followed, and
  the read can leave the configured root. This contradicts the containment the
  module docstring promises; `read_path`'s contract is one check short.

**Classification: open candidate, not a confirmed exploit.** [Unverified]
Exploitability has not been demonstrated; it requires write access to the
directory holding the target entry and a race against the MCP server's read
(e.g. same-UID attacker or hostile workspace content paired with a racing
writer). The affected tools are read-only (`scan_path` and anything else built
on `read_path`), so the maximum plausible impact is reading arbitrary
same-UID-readable bytes into an MCP response — an information disclosure
inside a boundary whose stated promise is root containment. It is a candidate
for the Phase 2 test plan, in a disposable environment.

## What is a risk reduction, not a sandbox (named)

[Verified]

1. Trusted executable/tool identity — "This module is a trust check, not a
   sandbox. A same-UID attacker can still replace an executable after
   revalidation, and root can replace the tools themselves."
   (`aurascan/core/trusted_executable.py:24-27`).
2. The post-scan `makepkg` handoff — "it is not a bounded scanner and not a
   sandbox; it is a deliberate, consented handoff" (`docs/SECURITY_BOUNDARIES.md:129-131`);
   it executes package build logic.
3. The devtools build sandbox — "not a sandbox guarantee": shared host kernel,
   `.INSTALL` hooks still run as root at install, base chroot trusted but
   unprovable (`docs/AUR_SANDBOX_DESIGN.md:54-72`).
4. Recovery `arch-chroot` execution — "risk reduction, not containment: an
   intact target tool still runs the target's own hooks and configuration as
   recovery root, a chroot is not a security boundary for a UID-0 process"
   (`docs/SECURITY_BOUNDARIES.md:184-193`).
5. The bounded archive/hook readers and provenance walk — incomplete
   inspection is a coverage result, never an all-clear
   (`docs/SECURITY_BOUNDARIES.md:316-325`).
6. The desktop renderer — a compromised renderer "can misdisplay evidence, not
   change a deterministic result or install anything" — with the
   `instruction_disable` consent caveat noted in Question 4.
