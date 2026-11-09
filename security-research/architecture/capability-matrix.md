# Capability matrix — baseline `02ac13d` (AuraScan 0.15.0, rules 1.15.0)

Execution identity, access and authority per component. "Identity" is the UID
the component runs as in its normal shipped mode, not what it *could* be run
as. `Unknown` marks a property source does not establish. Direct process call
sites (what `tools/architecture_audit.py` can see) are listed separately from
injected-runner execution (real authority the audit under-reports by design,
`docs/ARCHITECTURE.md:205-212`); both are credited here.

Audit cross-check 2026-11-09 (`python tools/architecture_audit.py --strict`,
exit 0): 6 modules hold a direct `process` call site — `core/agent.py`,
`core/local_package_db.py`, `core/package_archive.py`, `core/trusted_tools.py`,
`mcp/tools/security_audit.py`, `mcp/tools/security_audit_online.py`; 6 hold
`network` (`core/ai_provider.py`, `core/intelligence_transport.py`,
`core/recovery_boot.py`, `core/security_audit.py`, `core/source_acquisition.py`,
`core/upgrade_preflight.py`); 2 hold `privilege` (lookups only:
`core/config.py`, `core/intelligence_cli.py`). [Verified]

## Main matrix

| Component | Execution identity | Filesystem access | Network access | Execution authority | Consent requirement | Trust boundary |
| --- | --- | --- | --- | --- | --- | --- |
| **CLI** (`aurascan/cli.py`) | Invoking user (in pacman hook mode: pacman's privilege, i.e. root [Inference]) | Reads the scanned target + user config/state; writes bounded private state | None in default scan (offline by default) | Orchestrates scans; exits non-zero to block a transaction (`cli.py:606-613`) | None for scanning; consent sits on the actions it hands off to | Splits untrusted input (B1–B5) from deterministic policy |
| **Pacman hook mode** (`cli.py:226-380,606-613`, `packaging/arch/aurascan.hook`) | Root (runs inside the pacman PreTransaction hook, `AbortOnFail`) [Inference] | Reads `/var/cache/pacman/pkg` archives; no writes | None | Scan-only: blocks the transaction on findings | Installed hook is operator-approved at package-install time | B4 — cache archives are user-writable; each archive's identity must be *proven* from its own metadata (`cli.py:231-245`) before scanning |
| **makepkg wrapper** (`aurascan/makepkg_wrapper.py`) | Invoking user | Reads checkout + hooks; writes review/history state; hands cwd to makepkg | None itself (makepkg's own downloads are package-controlled — sanitized env + `BUILDFILE=` pin, `:623-631`) | **Executes package build logic** via `/usr/bin/makepkg` (`:84,502-513,623-631`) | Review acceptance + deliberate handoff; `sudo -k` before build (`:596-599`) | B9 — consented handoff, **not a sandbox**; recaptures full input identity before it (`:583-591`) and compares `.INSTALL` bytes after (`:633-660`) |
| **Trusted tools/executables** (`core/trusted_tools.py`, `core/trusted_executable.py`) | The caller's identity; tools fixed at `/usr/bin/<name>` | Opens only the fixed tool paths | None (the tools themselves are bounded by their callers) | Runs `git`/`gpg`/`bsdtar`/`clamscan`/`makepkg`/`sudo`/`pacman` with bounded input/output/runtime (`trusted_tools.py:15,115`; `trusted_executable.py:137`) | Inherits the calling workflow's consent | B8 — identity capture + revalidate-before-use (`trusted_tools.py:69-113`); explicitly "a trust check, not a sandbox" (`trusted_executable.py:24-27`) |
| **Build sandbox** (`core/build_sandbox.py`) | Host steps: invoking user + explicit `sudo` for root commands (`:539-560`); build steps: build user inside `extra-x86_64` chroot (`:82-85`) | Private `0700` work tree; chroot copy; cleanup `sudo rm -rf --one-file-system` (`:562-596`) | Inside the chroot: whatever the chroot network reaches (sources/deps) | `arch-nspawn`/`mkarchroot` builds; `sudo pacman -U` of hash-bound rescanned archives | Explicit opt-in only (`AURASCAN_AUR_SANDBOX=devtools` / `--aur-sandbox` / interactive accept; default `off`) | B10 — risk reduction: shared host kernel, `.INSTALL` still runs as root at install, base chroot unprovable (`docs/AUR_SANDBOX_DESIGN.md:54-72`) |
| **Recovery repair executor** (`core/recovery_repairs.py`) | Recovery root (UID 0 in the recovery environment) | Target filesystem via `arch-chroot`; backups + manifests | None | Executes target-resolved tools (pacman, pacman-key, mkinitcpio/dracut, dkms, snapper, bootloader installers) via `arch-chroot` (`:436-437,577,608,613,647,684,762,770,804`) | Typed confirmation phrase per action (`:881-918`); fresh per action | B11 — target tools validated root-owned/non-symlink (`:100-128`); chroot is **not** a boundary for UID 0; compromised target stays untrusted |
| **Incident/repo repair** (`core/incident_repairs.py`, `core/repository_repair.py`) | Invoking user or root; privileged steps via `sudo` helper (`incident_repairs.py:497-503`) | Writes under `/etc`, `/var` backups; reads host state | None | Allowlisted repair catalog only (`trusted_repair_commands`, `incident_repairs.py:432`); root checks (`:718`) | Fresh just-in-time confirmation per exact command | B11 — request-file validation (`execute_repair_request`, `:526`) |
| **Intelligence updater** (`core/intelligence_transport.py`, `core/intelligence_cli.py`, store/crypto) | Download: unprivileged service account (`FETCH_ACCOUNT`, `intelligence_cli.py:211-215`); verify/install: root (`:129-131`) | Reads feed bytes; atomically installs verified snapshots | Yes — bounded feed download only; redirects refused (`intelligence_transport.py:56-106`) | Updates detection data inside the validated contract; GnuPG verification network-isolated | Explicit refresh or separately enabled timer | B12 — unprivileged download separated from privileged verification; rollback/expired/changed-sequence rejected |
| **MCP server** (`aurascan/mcp/server.py`, `tools/*`) | The MCP host's user (stdio JSON-RPC; no privilege of its own) | Bounded no-follow reads under configured roots (`mcp/guards.py:26-75`); empty write surface | Only `security_audit_online` fetches the campaign feed (opt-in, `openWorldHint: true`) | 2 of 6 tools carry one injected `subprocess.run` each (`security_audit.py:34-38`, `security_audit_online.py:119-121`), argv-only, bounded; rest are pure reads | Host-side tool invocation is the consent model; online audit is opt-in | B15 — read-only by design; **L1 open candidate** in `read_capped` (see trust-boundaries.md) |
| **Desktop main** (`desktop/electron/main.cjs`) | The desktop user | Spawn/kill child processes; native dialogs; reads no package bytes itself | None directly | Spawns only `/usr/bin/aurascan` with fixed argv vectors (`argv.cjs:19,178-265`); opens a terminal for `aurascan upgrade` (`main.cjs:239-270`) | Each mutating action is renderer-confirmed; main revalidates shapes/bindings | B14 — closed action catalog; 8 MiB stdout cap; stderr discarded; env allowlist |
| **Desktop preload** (`desktop/electron/preload.cjs`) | Renderer bridge | None | None | None — forwards 13 fixed invoke calls (`:12-30`) | n/a | B14 — no renderer-supplied executables, flags, or command strings |
| **Desktop renderer** (sandboxed Chromium) | Untrusted | None (sandbox, contextIsolation, no Node) | None beyond the page itself | Requests fixed action IDs only; can supply at most: provider/credential, non-secret AI config values, `file_id`/`report_id`/`sha256` shapes | Its own confirmation dialogs (forgeable — see trust-boundaries.md Q4) | B14 — pure view; install/downgrade actions are terminal-only (`ui_actions.py:134,149`) |
| **AI provider client** (`core/ai_provider.py`) | The calling workflow's identity | Reads config; writes nothing | Yes — HTTPS to cloud providers (own key) or loopback-only local providers (`:234-271,283-340`) | None. Output is data through strict validators | AI is separately opt-in per surface (`AURASCAN_AI_ENABLED`); storing a key ≠ enabling | B7 — redirects refused (`:163-164`), 1 MiB response cap (`:144`), proxies disabled for local; no cloud fallback from local |
| **AI merge points** (`analyzers/ai_static.py`, `core/instruction_guard.py` AI, `core/finding_explainer.py`, `core/agent.py` model output) | Caller's identity | Persist only accepted bounded fields | Through the provider client only | **Raise-only** on severity/prose; agent model output may only *propose* commands | Agent commands need fresh per-exact-command confirmation bound to `plan_hash` (`agent.py:2573-2576`) | B7 — deterministic policy authoritative (INV-006); rejected output never persisted |
| **Install-hook / package-archive paths** (`core/install_hook.py`, `core/package_archive.py`) | Caller's identity | No-follow bounded reads only (`install_hook.py:1109-1145`; `package_archive.py:397-416`) | None | None — evidence capture; missing/ambiguous hook fails closed | n/a | B1/B3 — a built `.INSTALL` member is mandatory evidence; incomplete capture is coverage, never "no hook" |
| **Repair Agent** (`core/agent.py`) | User session; privileged steps through a validated helper (`:2665-2705`) | Bounded per allowlisted command | None (remote/URL requests rejected by policy `:1600`, prompt `:1805-1806`) | Executes allowlisted shell builtins, `/usr/bin`/`/usr/sbin` read-only diagnostics, constrained `pacman` workflows (`:342-394`) | Fresh just-in-time confirmation per exact command; `user-shell` cannot run root commands (`:1709-1711`) | B11 — fail-closed allowlist; command hash binding; not "full control" |
| **Local state** (`core/cache.py`, `core/state_file.py`, `core/config.py`) | Caller's identity | Bounded private state, atomic writes, mode-checked | None | None | Approvals machine-and-UID bound | B13 — same-UID malware can attack state (acknowledged limit) |

## Direct process call sites (audit-visible)

| Module | What it runs | Bounds |
| --- | --- | --- |
| `core/trusted_tools.py` | The shared bounded runner for fixed system tools | 256 KiB output cap (`:15`), timeout, revalidation (`:115`) |
| `core/package_archive.py` | `bsdtar` member enumeration/capture | Bounded output, no-follow file opens (`:397-416`), trusted-tool identity (`:379`) |
| `core/local_package_db.py` | `pacman` queries (installed state) | Injected runner + trusted identity at the call site [Verified in audit output; call shape [Inference]] |
| `core/agent.py` | The privileged agent helper via validated argv | Allowlist + hash-bound consent (`:2524-2576`) |
| `mcp/tools/security_audit.py` | One `subprocess.run`, argv-only (`:34-38`) | Bounded; offline |
| `mcp/tools/security_audit_online.py` | One `subprocess.run`, fixed env (`:119-121`) | Bounded; `persist_refresh=False`, `state_root=None` (`:170-171`) |

## Injected-runner / bounded-helper execution (audit under-reports; credited here)

| Caller | Mechanism | What actually executes |
| --- | --- | --- |
| `makepkg_wrapper.py` | direct `subprocess_run` at handoff (`:623-631`) + injected seams | `/usr/bin/makepkg` builds |
| `core/build_sandbox.py` | injected runner (`build_in_sandbox`, `:361`) | `arch-nspawn` chroot builds, `sudo` root commands |
| `core/upgrade_preflight.py` | `run_trusted_command` (`trusted_executable.py:137`) | `sudo`/`pacman` queries and the upgrade handoff |
| `core/incident_repairs.py`, `core/repository_repair.py`, `core/kernel_module_autopilot.py`, `core/config_drift.py` | `run_bounded_command` / caller-supplied runner | sudo repair commands, DKMS checks, drift fixes |
| `core/recovery_repairs.py`, `core/recovery_boot.py` | caller-supplied runner (`_run`, `:277`) | `arch-chroot` recipes, boot-image tooling (e.g. `sbctl`, `:428-445`) |
| `core/intelligence_cli.py` / store | bounded helpers | GnuPG verification, atomic install |
| `core/security_audit.py` | bounded helpers | advisory/campaign queries (network-capable module) |

## Notes on `Unknown` and limits

- The exact UID of the MCP server depends on the MCP host configuration —
  `Unknown` beyond "the host's user".
- `core/recovery_boot.py`'s network access is declared by the audit; the exact
  endpoints and their consent model were not read line-by-line this round —
  `[Unverified]` beyond "network-capable".
- Every row is a statement about shipped code paths at `02ac13d`; none of it
  proves runtime behavior. Races, same-UID attacks and root-level compromise
  are out of scope for this table (see the attack-surface inventory's open
  assumptions).
