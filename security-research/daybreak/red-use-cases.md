# Red use cases — ranked, evidence-bound candidates

Assessment date: 2026-11-09. Baseline: `02ac13d`. Companion: `blue-vs-red.md`
(capability analysis), `readiness-assessment.md` (decision).

**What this file is:** a ranked list of the only offensive-security research
that is legitimately in scope for this program — work against **owned
components** (the AuraScan repository and its own surfaces) or **explicitly
authorized disposable environments** (inert fixtures, disposable VMs,
simulated target filesystems per `governance/authorization-scope.md`).

**What this file is not:** a work order. Nothing here is scheduled, authorized
to execute, or an application justification. Candidates whose value depends on
unmeasured model capability are marked `[Speculation]` and cannot be promoted
to work items until measured. Ranking is by (evidence strength × security
value ÷ provisioning cost), reasoned — not a metric.

**Explicitly never candidates** (outside authorization entirely): testing
against third-party repositories, the AUR service, package registries, upstream
projects, live attacker infrastructure, production machines, or external
services; any real malware deployment; anything on the daily host.

## Ranking

### 1. Privilege-handoff race validation: makepkg TOCTOU + sudo re-arm (A1, R9)

- **Research objective:** determine empirically whether the makepkg handoff
  window (`makepkg_wrapper.py:583-631`) can be raced by a same-UID adversary —
  executable swap after revalidation, checkout mutation racing the recapture,
  and sudo timestamp re-arming after `sudo -k` (`:596-601`).
- **Component(s):** `aurascan/makepkg_wrapper.py`, `core/trusted_executable.py`.
- **Evidence anchor:** the trusted-executable model states it cannot prevent
  same-UID post-revalidation replacement (`trusted_executable.py:24-27`
  [Verified]); red R9 describes the re-arm window `[Inference]`;
  `testing/privilege-boundaries.md` A7/A8 `NOT EXECUTED`/`OUT OF SCOPE`.
- **Environment:** disposable VM (or stubbed-sudo harness for the unprivileged
  leg); never the daily workstation.
- **Red vs Blue/local:** Red-intended subject matter ("exploit validation");
  Blue/local sufficient to author and review the harness on current evidence —
  Red value `[Speculation]`. See `blue-vs-red.md` C1.
- **Status:** ready to design; execution blocked on VM provisioning + fresh
  owner approval per test.

### 2. Sandbox scan→install artifact substitution (R3, R4, R10)

- **Research objective:** establish whether an artifact scanned at
  `makepkg_wrapper.py:1001` is provably the artifact installed at `:1059-1064`;
  whether `build_root/root` symlink substitution reaches `sudo cp -a` /
  `arch-nspawn` (R4); whether cleanup `sudo rm -rf` runs on revalidated
  identities (R10).
- **Component(s):** `core/build_sandbox.py`, `aurascan/makepkg_wrapper.py`.
- **Evidence anchor:** structural inspection shows the captured digest
  (`build_sandbox.py:709-716`) is display material and no re-bind exists
  between scan and install [red R3, `Inference`]; end-to-end `NOT EXECUTED`.
- **Environment:** disposable VM with a devtools base provisioned by the
  documented `mkarchroot` command; root for the `pacman -U` leg; fresh owner
  approval.
- **Red vs Blue/local:** fake-runner unit probes are Blue/local work; the
  root/chroot leg is a provisioning limit, not a model limit. Red value
  `[Speculation]`. See `blue-vs-red.md` C3.
- **Status:** highest-consequence open question in the red report; needs the VM
  round.

### 3. MCP `read_capped` race: fix verification and CI stress harness (R1/A2)

- **Research objective:** convert the demonstrated containment crossing into a
  permanent deterministic regression (swap-between-resolve-and-read test +
  threaded stress harness), and validate the fix contract (containment
  re-decided on the opened descriptor).
- **Component(s):** `aurascan/mcp/guards.py:26-84` (+ `_contains` root-`/`
  bug R2 alongside).
- **Evidence anchor:** executed probe returned outside-root bytes through the
  capped read after a post-resolution symlink swap (red `l1_probe.py`, exit 0,
  2026-11-09; reviewer gate pending). First demonstrated boundary crossing of
  the program.
- **Environment:** unprivileged; temporary roots; inert data — runnable without
  a VM.
- **Red vs Blue/local:** fully Blue/local-deterministic; no Red value
  identified. See `blue-vs-red.md` C2.
- **Status:** unblocked; belongs to ordinary remediation (owner authorization
  required for the fix itself — findings first, per charter §15).

### 4. Detector-bypass variant campaign (Phase 3 expansion)

- **Research objective:** measurably stress the deterministic detectors with
  semantically equivalent evasive variants across surfaces without a corpus
  case (no surface→case mapping has been established;
  `testing/detector-benchmark.md` §6), with benign controls, and produce
  detection/FN/FP rates per threat category.
- **Component(s):** S1/S2/S15/S16 analyzers (attack-surface inventory).
- **Evidence anchor:** corpus v1.0.0 baseline measured 4/4 detection, 0/4 FN
  (worker, exit 0) — on nine cases; the charter's variant matrix is uncovered.
- **Environment:** inert fixtures in-tree; nothing executes.
- **Red vs Blue/local:** strongest subject-matter case for Red (adversarial
  evasion tradecraft), **but** generation quality by any model is unmeasured —
  Red value `[Speculation]`. A model-comparison experiment (local vs Blue vs
  Red on identical variant briefs) is the honest prerequisite. See
  `blue-vs-red.md` C4.
- **Status:** partially unblocked (existing corpus runnable now); scaling is
  authoring work.

### 5. AI evidence-laundering chains (Phase 5)

- **Research objective:** exercise the charter's Phase 5 categories against the
  project's own AI boundaries with mocked transports (or separately approved
  local targets), measuring model-level susceptibility separately from
  end-to-end compromise.
- **Component(s):** `analyzers/ai_static.py`, `core/instruction_guard.py` AI,
  `core/agent.py`, `core/finding_explainer.py`.
- **Evidence anchor:** Phase 5 `NOT EXECUTED`; red's static review found no
  audited AI surface converting output into execution authority (scope-limited;
  gate pending); S12 is rank 7 of 15 ranked attack surfaces.
- **Environment:** mocked transports; no credentials, no provider spend; any
  live evaluation needs explicit owner authorization.
- **Red vs Blue/local:** Red could plausibly produce more effective
  adversarial payloads; effect `[Speculation]`, unmeasured. See
  `blue-vs-red.md` C5.
- **Status:** design-ready; execution limited to mocked transports this round.

### 6. Recovery-target compromise chains (A6, R5, R7) [partly Speculation]

- **Research objective:** build a hostile-but-simulated target filesystem and
  determine what observable difference exists between "clean repair" and
  "target compromised"; validate R5's latent `snapshot_id` traversal and R7's
  bare-name tool resolution under a controlled recovery runtime.
- **Component(s):** `core/recovery_repairs.py`, `core/recovery_boot.py`.
- **Evidence anchor:** documented "chroot is not a boundary for UID 0"
  (`docs/SECURITY_BOUNDARIES.md:184-193` [Verified]); R5 reachability currently
  latent `[Inference]`; end-to-end `NOT EXECUTED` (needs root-owned fixtures).
- **Environment:** simulated target + root-owned fixtures; destructive tests
  excluded; fresh owner approval.
- **Red vs Blue/local:** chain composition value `[Speculation]`; deterministic
  fixtures carry the load. See `blue-vs-red.md` C7.
- **Status:** blocked on fixtures/VM.

### 7. Desktop IPC consent-forgery fuzzing (A4)

- **Research objective:** drive all 13 preload channels with a
  simulated-compromised renderer and enumerate state changes achievable without
  a genuine user click (the `instruction_disable --yes` path at
  `argv.cjs:237` is the known residual).
- **Component(s):** `desktop/electron/main.cjs`, `argv.cjs`, `preload.cjs`.
- **Evidence anchor:** structural claim verified in the baseline
  (`architecture/trust-boundaries.md` Question 4); impact `[Speculation]`;
  desktop vitest suites `NOT EXECUTED` in the baseline round.
- **Environment:** the project's own desktop shell under test harnesses; no
  host mutation.
- **Red vs Blue/local:** mechanical fuzzing; Red value not identified. See
  `blue-vs-red.md` C8.
- **Status:** unblocked once the vitest environment is run (that itself is
  pending from the baseline card's follow-ups).

### 8. Intelligence-feed trust-chain attacks (A10) `[Speculation]`

- **Research objective:** exercise rollback/schema/reset attacks through the
  public interface of the updater against a mock feed.
- **Evidence anchor:** controls verified in source (attack-surface inventory
  S10); no adversarial test exists. Value depends on threat realism for a feed
  that is fingerprint-pinned and GnuPG-verified — hence `[Speculation]`.
- **Environment:** mock feed, unprivileged; never the live feed.
- **Red vs Blue/local:** no identified Red value.

## Ideas that were considered and excluded

| Idea | Why excluded |
| --- | --- |
| Testing the AUR service, `aur.archlinux.org`, or upstream packages | Outside authorization entirely (charter §2) |
| Deploying real exploit infrastructure / C2-style callbacks | Violates inert-fixture invariants (`AGENTS.md`); no need exists |
| Kernel/chroot escape research against the devtools sandbox | Explicitly out of scope of the product's own guarantee (`docs/AUR_SANDBOX_DESIGN.md:58-59`); not an owned-kernel boundary |
| Exploiting third-party tools (`bsdtar`, `gpg`, Electron) | Findings would belong upstream; AuraScan treats them as trusted-boundary inputs with bounds; out of this program's scope |
| Any use of Red capability against systems other than AuraScan/authorized disposable environments | Violates Daybreak's own intended-use restriction (owned/authorized targets only) and this program's charter |

## Promotion rule

A candidate moves from this list to an authorized test only with: (1) an owner
approval naming exact commands, environment, privilege needs, rollback and
side effects (`governance/authorization-scope.md` fresh-approval rule); (2) a
disposable environment where required; (3) a finding record template ready
(`governance/vulnerability-handling.md`). `[Speculation]`-valued Red claims
additionally require a measured model comparison before they can inform any
Red decision.
