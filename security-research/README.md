# Daybreak security research program

Status: **NOT READY** (baseline round — reconnaissance only; no adversarial
tests have been executed yet). This tree is the public scaffold of AuraScan's
security validation and evidence program. It exists to make the project's real
trust boundaries auditable and to record, with evidence, *whether and when* an
offensive-security research capability (OpenAI Daybreak Red) would become
technically justified.

This document does **not** claim that AuraScan is ready for any application,
that Red access is necessary, or that any check described here proves safety.
AuraScan is developed independently and is not an enterprise; no organizational
credentials are claimed.

- Baseline revision: `02ac13d` (AuraScan 0.15.0, rule catalogue 1.15.0,
  `aurascan/core/engine.py:108`).
- Architecture measurement at baseline: `python tools/architecture_audit.py
  --strict` exited `0`; 135 modules, 87,315 physical lines, zero invariant
  violations (19 invariants). [Verified 2026-11-09]
- Owner instruction: `findings/daybreak/PROGRAM-CHARTER.md` (SHA-256
  `2c7b5e019dacd9fd60442b5587f3cfe034ce718b0da8464669c1a607e99796fc`).
- Shared verified-facts block: `findings/daybreak/ORCHESTRATOR-BRIEF.md`.

## Contents

| File | What it holds |
| --- | --- |
| [`architecture/trust-boundaries.mmd`](architecture/trust-boundaries.mmd) | Mermaid flowchart: trust boundaries, privilege transitions, consent gates, AI authority |
| [`architecture/trust-boundaries.md`](architecture/trust-boundaries.md) | The same model in prose with `path:line` evidence; boundary table; doc-vs-source discrepancies |
| [`architecture/capability-matrix.md`](architecture/capability-matrix.md) | Per-component identity, filesystem/network access, execution authority, consent, boundary |
| [`architecture/attack-surface-inventory.md`](architecture/attack-surface-inventory.md) | Ranked attack surfaces, open assumptions for later Red tests, evidence labels |
| [`governance/authorization-scope.md`](governance/authorization-scope.md) | Authorized environments, prohibited tests, fresh-approval rule |
| [`governance/responsible-disclosure.md`](governance/responsible-disclosure.md) | Private evidence handling, sanitized summaries, owner disclosure decision |
| [`governance/vulnerability-handling.md`](governance/vulnerability-handling.md) | Finding IDs, severity/confidence separation, retest, remediation rules |

Files under `security-research/testing/`, `security-research/evidence/` and
`security-research/daybreak/` are owned by other roles and are not created
here.

## Evidence labels

Every significant claim carries one of:

- **[Verified]** — demonstrated by source inspection, executed command, or
  authoritative evidence in this round.
- **[Inference]** — reasoned conclusion supported by available evidence.
- **[Speculation]** — plausible scenario, not yet demonstrated.
- **[Unverified]** — cannot currently be independently confirmed (e.g. needs a
  file or environment outside this round's scope).

A passing test establishes the behavior of the tested configuration only. It
does not prove that the system is safe, that untrusted content is benign, or
that nothing executed.

## Scope of this round

Authorized (from `ORCHESTRATOR-BRIEF.md`):

- Read-only inspection of this repository and local development copies.
- Inert fixtures in temporary directories, synthetic credentials, unit-level
  calls that do not execute package, hook, fixture, or agent-instruction
  content.
- Existing test suites and read-only audit tools.
- Web retrieval of public OpenAI and AuraScan documentation.

Prohibited (see `governance/authorization-scope.md` for the full list): tests
against third-party infrastructure; running AUR builds, `makepkg`, package
installation, sudo, root brokers, or recovery actions; executing malicious
fixtures on this workstation; changing CI, release, dependency, or secret
state; publishing exploit artifacts; applying fixes to discovered
vulnerabilities without owner authorization.

## Public / private split

- **Public (this tree):** sanitized architecture analysis, capability matrix,
  attack-surface inventory with evidence labels, governance documents, and
  sanitized test/benchmark summaries. Public material may reference private
  evidence IDs but never contain exploit artifacts, working attack details,
  credentials, private user paths, or raw hostile bytes.
- **Private (outside the repository, at `<private evidence root>`):**
  raw adversarial evidence, exploit reproduction details, candidate-vulnerability
  records, and anything whose publication would help an attacker before a fix
  exists.

## Program design

### Phase sequence, entry/exit criteria, ownership

The charter's ten phases map onto the council roles as follows. "Owner" is the
role accountable for the phase's evidence; the reviewer independently gates
every completed phase.

| Phase | Content | Entry criteria | Exit criteria | Owner |
| --- | --- | --- | --- | --- |
| 1. Reconnaissance & architecture mapping | Trust boundaries, capability matrix, attack-surface inventory (this round) | Charter + brief read; baseline pinned | Deliverables written; audit re-run and recorded | `architect` |
| 2. Privilege-boundary validation | Trusted-executable integrity, consent/replay, repair/recovery tests | Phase 1 done; disposable environment provisioned; fresh owner approval for anything elevated or destructive | Tests executed in the approved environment; actual results recorded (not expected behavior) | `red` designs, `worker` implements harness |
| 3. Detector-bypass benchmark | Versioned fixture corpus, detection/FN/FP rates, benign controls | Phase 1 done; corpus version frozen | Metrics computed from executed runs and bound to evidence records | `worker` (corpus), `red` (families) |
| 4. Chained malicious-package simulations | Multi-component chains (AUR build+install, AI-assisted repair, recovery) | Phases 2–3 done; disposable environment | Each boundary crossed/not crossed recorded with evidence | `red` + `worker` |
| 5. AI prompt-injection / evidence-laundering tests | Injection through every untrusted-into-model path | Phase 1 AI data-flow map done; mocked transports only unless owner approves live calls | Model-level susceptibility separated from end-to-end compromise | `red` |
| 6. CI/CD & supply-chain assessment | Workflows, pinning, release provenance, update-channel integrity | None beyond Phase 1 | Risks documented; no permission/workflow changes made | `architect` |
| 7. Blue vs. local vs. Red capability assessment | Per-category work assessment against current OpenAI docs | Phase 1 done; authoritative docs retrieved with dates/URLs | Recommendation with evidence, gaps marked `[Unverified]` where docs unavailable | `architect` (follow-up card) |
| 8. Application-trigger evaluation | Five triggers, decision class | Phases 2–5 evidence (or their absence) recorded | Decision class assigned; no trigger manufactured | `architect` + owner |
| 9. Dossier assembly | 17-section dossier | Phases 1–8 complete | Dossier complete or gaps explicitly `NOT READY`/`[Unverified]` | `architect` |
| 10. Continuous evidence collection | Release-bound evidence, metric deltas, re-assessment | Program established | Each release gets an evidence record and a trigger comparison | `worker` + `reviewer` gate |

### Evidence versioning and binding

Every evidence record (test result, benchmark row, finding) is bound to:

1. **Git revision** — full commit SHA of the tested tree (baseline:
   `02ac13d`).
2. **AuraScan version** — `pyproject.toml` version (baseline `0.15.0`).
3. **Rule version** — `aurascan/core/engine.py:108` (`1.15.0`). A changed rule
   version invalidates cross-version detection comparisons.
4. **Fixture hash** — SHA-256 of every fixture byte the record depends on.
5. **Environment** — OS/kernel, Python version, image/VM identity (digest or
   provisioning recipe hash), and any relevant tool versions.
6. **Command and exit code** — the exact command line and its exit code.

Records missing any binding are unusable for cross-release comparison and must
be re-run. Evidence artifacts are hashed (SHA-256) in the evidence index;
timestamps are recorded in UTC.

### Isolation model

| Environment | Allowed work | Never allowed |
| --- | --- | --- |
| **This workstation** | Read-only inspection; inert unit tests; existing test suites; read-only audit tools; fixtures that are parsed as data only | Executing package code, hooks, fixtures, downloaded source, `makepkg`, package installation, sudo, recovery actions, live exploit attempts |
| **Disposable container** | Inert-to-moderate adversarial fixtures that must run (e.g. parser fuzz corpora) | Anything needing a distinct kernel or real block devices; container shares the host kernel |
| **Disposable VM** | Privilege-boundary tests, build/handoff chains, recovery scenarios, deliberately hostile fixtures | Running on the daily host; keeping state between runs |
| **External isolated lab** | Only after owner approval: realistic exploit behavior that exceeds disposable-VM fidelity | Anything against third-party systems |

Destructive tests and tests needing elevated privileges require **fresh owner
approval per test** (see `governance/authorization-scope.md`). A VM snapshot
rollback is the standard reset between tests.

### Detector-bypass finding vs correct fail-closed coverage

- **Detector-bypass finding:** malicious behavior that falls inside a declared
  rule's or contract's intended detection scope is presented as clean/allowed
  (no finding, no coverage flag, no review requirement) — i.e. the scanner
  *claims* coverage it does not have. A bypass needs a demonstrated behavior in
  scope plus an observed all-clear.
- **Correct fail-closed coverage:** the scanner reports incomplete inspection,
  blocks, or requires manual review — e.g. a source it cannot inspect is
  blocked (`UPG-AUR-BUILD-UNSCANNED`), malformed arrays fail closed, a
  changing hook refuses. Unmodeled behavior reported as *coverage* is a
  feature gap, not a bypass. "Not detected" never equals "safe".

### Daybreak triggers and decision classes

Five independent trigger categories (charter §10). No finding may be
manufactured to meet a trigger, and no finding may be withheld to avoid one.

| # | Trigger | State at baseline |
| --- | --- | --- |
| 1 | Privilege-boundary testing demonstrates a genuine boundary weakness or credible need for deeper exploit validation | Not yet tested — Phase 2 `NOT EXECUTED` |
| 2 | Versioned detector-bypass benchmark shows measurable misses of security-relevant behavior | Not yet measured — Phase 3 `NOT EXECUTED` |
| 3 | Controlled fixture demonstrates a meaningful weakness spanning multiple components | Not yet tested — Phase 4 `NOT EXECUTED` |
| 4 | Reproducible AI prompt-injection/evidence-laundering failure affecting a security decision | Not yet tested — Phase 5 `NOT EXECUTED` |
| 5 | Verified external exposure: adoption, external vulnerability reports, malicious contribution attempts, attacker attention | Unknown — unknown adoption is not zero adoption |

Decision classes: **NOT READY** (no meaningful Red justification),
**PREPARE** (credible justification, evidence/eligibility incomplete),
**APPLY WHEN ELIGIBLE** (concrete program justified and requirements met),
**URGENT SECURITY RESPONSE** (serious vulnerability needs remediation
regardless of Daybreak). Current class: **NOT READY** — the evidence that
could move it does not exist yet.

## Program options and recommendation (owner question 2)

Three ways to run the evidence program:

| | (a) Workstation-only inert unit tests | (b) Disposable container/VM harness | (c) External isolated lab |
| --- | --- | --- | --- |
| Cost | Near zero; runs in CI | Moderate: VM image provisioning, snapshot tooling; per-run minutes | High: dedicated environment, human time, coordination |
| Reproducibility | High: pure Python, pinned by git SHA | Good: pinned image + snapshot reset; kernel/tool versions must be recorded | Lower: bespoke environment drifts unless heavily scripted |
| Safety | Highest: nothing executes | High if strictly disposable and network-controlled; container shares host kernel — prefer VM for privilege tests | Highest containment for genuinely hostile content |
| What it cannot prove | Nothing about runtime behavior: no TOCTOU, no privilege transitions, no real hooks/makepkg/sudo/chroot | Cannot prove behavior on the daily host's kernel/config state; chroot/container is not a kernel boundary | Cannot be run continuously or per-release; results age; overkill for routine regression |

**Recommendation for the next round: (b), a disposable VM harness**, with (a)
kept running continuously as the CI regression layer. The charter's Phase 2–4
questions (trusted-executable races, consent replay, handoff chains, recovery
target manipulation) are questions about *runtime* privilege transitions and
cannot be answered by inert parsing tests; but they are still bounded,
owned-component tests that need only a disposable environment, not an external
lab. Workstation-only testing would leave the highest-value boundaries
untested, and an external lab cannot be justified before any boundary weakness
has even been measured.

**What would change my mind:** evidence that the Phase 2–4 tests can be
expressed entirely as inert unit-level checks with no host behavior in play
(downgrade to (a)); or a confirmed boundary-crossing finding whose validation
requires realistic exploit development beyond disposable-VM fidelity (escalate
to (c) and re-evaluate the Daybreak triggers immediately).

## NOT EXECUTED in this round, and why

Everything below is deliberately not executed. Reasons: this round is
read-only reconnaissance under `ORCHESTRATOR-BRIEF.md` scope; executing any of
it here would violate the authorization boundary or the safety invariants in
`AGENTS.md`.

| Not executed | Why |
| --- | --- |
| Privilege-boundary exploit tests (symlink races, consent replay, executable substitution) | Need a disposable environment and per-test owner approval (Phase 2) |
| Disposable-VM / container adversarial runs | Not provisioned this round; harness is a later card |
| Live AI provider calls | No credentials, no provider spend; all AI transports stay mocked |
| `makepkg`, AUR builds, package installation, sudo, `arch-chroot`, recovery actions | Prohibited on this workstation |
| Network scans and third-party targeting | Outside authorization entirely |
| Detector-benchmark measurement runs | Corpus and harness are `worker`'s card |
| External outreach / application submission | Prohibited; owner decision point |
| Fresh full-suite re-run | **Executed** (read-only, existing tests only). 2026-11-09: `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q` → **5,714 passed, 3 skipped, exit 0**; the same suite under this runtime's default PATH → 33 failed, 5,681 passed, 3 skipped, exit 1. The 33 failures (28 `tests/test_source_acquisition.py`, 4 `tests/test_git_signature_verification.py`, 1 `tests/test_recovery.py`) are environment artifacts: this runtime's PATH lists `/usr/sbin` before `/usr/bin`, so `capture_trusted_system_tool` refuses `git`/`lsblk` by design (PATH must resolve to `/usr/bin/<name>`, `aurascan/core/trusted_tools.py:69-80`) and the affected tests observe `skipped` instead of `failed`; both representative tests pass under the sanitized PATH (`2 passed, exit 0`). No detection or policy regression was measured. The fail-closed refusal itself is intact — no untrusted tool executed. [Verified] |

## Owner's questions — where answered

1. **Boundary analysis** (execution authority vs. rendering; unsupported doc
   claims) → `architecture/trust-boundaries.md`, "Question 1".
2. **Privilege transitions** (what is revalidated before each crossing) →
   `architecture/trust-boundaries.md`, "Question 2".
3. **AI authority** (where model output influences decisions; the
   deterministic gate) → `architecture/trust-boundaries.md`, "Question 3".
4. **Desktop boundary** (renderer requests vs. main-process refusals) →
   `architecture/trust-boundaries.md`, "Question 4".
5. **Open assumptions for later Red tests** →
   `architecture/attack-surface-inventory.md`, "Open assumptions".
6. **Program options and recommendation** → this file, "Program options and
   recommendation".
