# Blue vs. local models vs. Red — capability assessment

Assessment date: 2026-11-09. Baseline: `02ac13d`, AuraScan 0.15.0, rule
catalogue 1.15.0. Companion files: `eligibility.md` (program requirements),
`red-use-cases.md` (ranked candidates), `readiness-assessment.md` (decision).

## 0. Method and its limits (read first)

- **No live model calls were made this round** (`ORCHESTRATOR-BRIEF.md`
  prohibits credentials and provider spend). Therefore **no model refusal and
  no weak model output has been observed anywhere in this assessment.** Every
  statement about what Blue, Red, or a local model "can" or "cannot" do is
  `[Inference]` from documented intended use and the deterministic character of
  the work — not a measured model evaluation. Per the charter (§9) a refusal or
  weak answer is never proof that Red is required; here there are not even
  refusals to misuse.
- The **measured baseline** this assessment rests on:
  - Architecture (`t_c667ed14`): 15 trust boundaries, 15 ranked attack
    surfaces (S6 is described but not ranked), 10 open assumptions A1–A10;
    `tools/architecture_audit.py
    --strict` exit 0 (135 modules, 87,315 lines, 0 violations); full suite
    5,714 passed / 3 skipped under sanitized PATH.
  - Red role (`t_41563ead`, 2026-11-09): 10 findings — R1, R2, R6 confirmed
    by executed inert probes (exit 0); R8 verified by source inspection,
    caller-disclosure impact NOT EXECUTED; R3, R4, R5, R7, R9, R10
    inference-level, root/VM validation `NOT EXECUTED`. Independent reviewer
    gate (`t_32ee3ab1`) **pending** — findings are cited as reported by the
    red role.
  - Worker role (`t_1503aa02`, 2026-11-09): detector corpus v1.0.0 (9 cases,
    4 families) — detection 4/4, false negatives 0/4, false positives 0/1 per
    family; regression `not measured`; large surfaces without any corpus case.
- **"Technical limitation" vs. "model behavior"** is separated throughout: a
  limitation is only claimed where a deterministic mechanism (parser, boundary,
  consent gate) was shown to behave a certain way. Model-side rows say
  explicitly that nothing was measured.

## 1. Table A — Work adequately supported by Blue (or standard safeguards)

Blue's documented intended use: "Vulnerability triage, secure code review,
malware analysis, detection engineering, incident response, and patch
validation" (help.openai.com 20001258, retrieved 2026-11-09). Standard
mainline usage already covers "threat modeling, secure code reviews and
patching, as well as generalized blue teaming" (same source).

| # | Work | Program phase | Why Blue/standard suffices | Evidence |
| --- | --- | --- | --- | --- |
| A1 | Trust-boundary / threat-model analysis | Phase 1 | Was completed this round with **no model at all** (source inspection + read-only audit) | `security-research/architecture/*`; `t_c667ed14` |
| A2 | Vulnerability triage of the R1–R10 findings and A1–A10 assumptions | Phase 2 prep | Triage, severity/confidence separation, remediation review are Blue's named use cases | `security-research/governance/vulnerability-handling.md`; red report |
| A3 | Secure code review and patch review (fixing R1/R2/R6/R8, e.g. the `read_capped` containment gap) | Remediation | Patch validation/review is named Blue use; fixes are ordinary engineering | red report findings R1, R2, R6, R8 |
| A4 | Defensive detection engineering: new rules and corpus families for the uncovered surfaces | Phase 3 | Detection engineering is a named Blue use; corpus v1.0.0 was authored without any model | `security-research/testing/detector-benchmark.md` §6 (coverage gaps) |
| A5 | Static malware analysis of hostile PKGBUILD/hook/npm constructs (understanding what a fixture does) | Phase 3 | Malware analysis is a named Blue use; all analysis is static and inert | `tests/security_research/test_detector_corpus.py`; AGENTS.md invariants |
| A6 | Security regression-test design and interpretation of suite results | Continuous | Standard SDLC work under standard safeguards | 5,714-pass baseline; `t_1503aa02` probe log |
| A7 | Drafting sanitized summaries, disclosure material, and finding records | Governance | Defensive documentation; owner decides disclosure | `governance/responsible-disclosure.md` |
| A8 | Explaining red-role findings to the maintainer (decision support) | All | Advisory interpretation; deterministic policy stays authoritative (INV-006) | `architecture/trust-boundaries.md` Question 3 |

## 2. Table B — Work local models can perform

Local model inventory on this workstation is `[Unverified]` (AuraScan's own
runtime supports loopback `lmstudio`/`llamacpp` providers — `AGENTS.md` — but
no live call was made and no provider was contacted). Rows describe the work's
fit, `[Inference]`, not measured performance.

| # | Work | Why a local model suffices | Inherent limit of the work item (not of any model) |
| --- | --- | --- | --- |
| B1 | Generating inert fixture variants (formatting, variable expansion, encoding, indirection) for the detector corpus | Syntactic transformation of known patterns; corpus fixtures were hand-authored with no model | Variants must stay inert and defanged (`AGENTS.md`); generated fixtures are exposed/public, not a private holdout |
| B2 | Authoring deterministic test-harness code (race harnesses, fake runners) | Ordinary code generation; harnesses are unit-level Python (pytest) | Correctness is proven only by running the harness, never by the model |
| B3 | Static-analysis assistance (reading parsers, listing constructs) | Reading and summarizing code is baseline model work | Every claim must still be verified at `path:line` by the implementer |
| B4 | Threat-model drafting and refinement | Prose + structure work | Source-grounded claims need human/tool verification |
| B5 | Reproducing a finding from a written procedure | Following explicit steps | Reproduction evidence comes from the executed run, not the model |
| B6 | Adversarial test *planning* (Phase 5 injection corpus design, Phase 4 chain scripts) | Planning is language work | The charter's safety limits (inert payloads, mocked transports) bind regardless of who plans |
| B7 | Summarizing benchmark runs and drafting assessment updates | Prose work | Numbers must be copied from executed output (external_state_verification) |

**Nothing in the measured baseline indicates local models cannot do this work
— and nothing indicates they can at a given quality either.** No local-model
evaluation was run (prohibited this round). This is an explicit `[Unverified]`
in both directions; it cannot be used to argue for or against Red.

## 3. Table C — Work that could justify Red (candidates)

Red's documented intended use: "Authorized penetration testing, red teaming,
exploit validation or development, and controlled vulnerability research"
(help.openai.com 20001258, retrieved 2026-11-09). The rows below are the only
work in the program whose *subject matter* matches that description. Each is
then examined honestly in §4: **matching Red's intended use is not the same as
requiring Red's capabilities.**

| # | Candidate | Component | Phase | Subject matter vs Red intended use | Red-necessity on current evidence |
| --- | --- | --- | --- | --- | --- |
| C1 | Exploit-chain validation of the makepkg handoff TOCTOU window (A1, R9) | `aurascan/makepkg_wrapper.py` | 2 | Exploit validation ✓ | **Not established** — a deterministic race harness is the tool; no model needed to write or run it |
| C2 | End-to-end race PoC hardening for the MCP `read_capped` containment gap (R1/A2) | `aurascan/mcp/guards.py` | 2 | Controlled vulnerability research ✓ | **Not established** — the crossing was already demonstrated by an inert probe (red, exit 0) |
| C3 | Sandbox artifact substitution validation (R3, R4, R10) | `core/build_sandbox.py`, `makepkg_wrapper.py` | 2/4 | Exploit-chain validation ✓ | **Not established** — needs a disposable VM + devtools base, not a model |
| C4 | Detector-bypass variant generation at scale (Phase 3 expansion across surfaces without a corpus case) | deterministic/nm/npm/provenance analyzers | 3 | Offensive tradecraft applied to owned detectors ✓ | **Weak/possible** — creative evasive-variant generation is where a cyber model plausibly adds quality; not measured |
| C5 | AI evidence-laundering / prompt-injection chain design (Phase 5) | `analyzers/ai_static.py`, `core/instruction_guard.py`, `core/agent.py` boundaries | 5 | Controlled adversarial testing ✓ | **Weak/possible** — crafting effective injections is dual-use model work where reduced refusals could matter; not measured |
| C6 | Chained malicious-package simulations (charter Phase 4 chains A/B/C) | wrapper + hooks + recovery | 4 | Multi-stage attack simulation ✓ | **Not established** — chains are scripted deterministic workflows |
| C7 | Recovery-target compromise chains (A6, R5, R7) | `core/recovery_repairs.py`, `core/recovery_boot.py` | 2/4 | Controlled vulnerability research ✓ | **Not established** — needs simulated target fixtures + root-owned test fixtures |
| C8 | Desktop IPC consent-forgery fuzzing (A4) | `desktop/electron/*` | 2 | Red teaming of an owned surface ✓ | **Not established** — channel fuzzing is mechanical |

## 4. Red candidates in detail

Format per charter §9: objective; component; why necessary; what Blue can and
cannot do; what local models can and cannot do; observed limitation with
reproducible evidence; why Red would materially improve the research;
safeguards/scope. **"Why necessary" is answered with the current evidence
standard: a need is only "necessary" if no existing tool can produce the
required artifact. On today's evidence, none of these crosses that bar.**

### C1 — makepkg handoff TOCTOU (A1, R9)

- **Objective:** convert assumption A1 (`trusted_executable.py:24-27`
  acknowledged same-UID swap window) and finding R9 (sudo timestamp re-arm
  window, `makepkg_wrapper.py:596-601`) into measured findings or retire them.
- **Component:** `aurascan/makepkg_wrapper.py` handoff (`:623-631`), trusted
  executable model.
- **Why necessary:** it is the highest-impact handoff in the product (package
  build logic executes); the wrapper's own recapture discipline (`:583-591`)
  has never been tested against a real racing adversary.
- **Blue can:** analyze the window, design the harness, review results (the red
  role's structural findings were produced without Red). **Blue cannot:** —
  nothing demonstrated it cannot do here.
- **Local models can:** harness code, fixture scripts. **Cannot (inherent to
  the work):** execute the race — that is a VM/runtime job, model-independent.
- **Observed limitation (reproducible evidence):** none of any model. The
  deterministic gap is documented: `NOT EXECUTED` per `red-privilege-boundaries.md`
  (R9) and `testing/privilege-boundaries.md` A7/A8 (`OUT OF SCOPE` this round).
- **Why Red would materially improve:** `[Speculation]` — a cyber model may
  accelerate race/PoC authoring ("exploit validation" is Red's exact use case).
  Not measured; a competent harness author suffices on current evidence.
- **Safeguards/scope:** disposable VM only; synthetic sudo stub or disposable
  user session; fresh owner approval per the authorization-scope rule; never on
  the daily host.

### C2 — MCP `read_capped` containment race (R1 / open candidate L1)

- **Objective:** stress-test and fix-verify the containment race already
  demonstrated; produce a CI-able race harness.
- **Component:** `aurascan/mcp/guards.py:61-84`.
- **Why necessary:** R1 is the program's first **executed** boundary crossing
  (red probe: a resolved entry swapped for a symlink returned outside-root
  bytes through the capped read — information disclosure across a documented
  containment promise). Fix validation needs a deterministic regression test.
- **Blue can:** everything required — code review, test design, fix review.
  **Local models can:** harness code.
- **Observed limitation:** none of any model. Deterministic evidence exists:
  probe executed, exit 0 (red `l1_probe.py`, 2026-11-09; reviewer gate
  pending).
- **Why Red would materially improve:** no material improvement identified;
  the finding is already demonstrated and the remediation is a two-line
  contract fix plus tests.
- **Safeguards/scope:** unprivileged, temporary roots, inert data.

### C3 — sandbox artifact substitution (R3, R4, R10)

- **Objective:** end-to-end validation, in a disposable VM with a devtools
  base, of whether artifacts scanned at `makepkg_wrapper.py:1001` are the bytes
  installed at `:1059-1064` (R3), plus the `build_root/root` symlink question
  (R4) and cleanup identity revalidation (R10).
- **Component:** `core/build_sandbox.py`, `aurascan/makepkg_wrapper.py`.
- **Why necessary:** R3 describes a scan-verdict/install mismatch class —
  highest-consequence inference in the red report (root-installed attacker
  bytes despite a scan). It is `[Inference]` and needs the VM round to confirm
  or retire.
- **Blue can:** structural analysis (already done), unit probes with fake
  runners (red recommended exactly these). **Blue cannot:** run the root/chroot
  leg — but that is a *provisioning* limitation, not a model limitation.
- **Local models can:** fake-runner unit probes. **Cannot (inherent):** provide
  a devtools chroot base and root.
- **Observed limitation:** none of any model. `NOT EXECUTED` (red R3/R4/R10:
  needs disposable VM/chroot host + root).
- **Why Red would materially improve:** `[Speculation]` — exploit-chain
  assembly assistance; unnecessary for the described tests.
- **Safeguards/scope:** disposable VM; documented `mkarchroot` base; hash-bound
  artifacts; fresh owner approval; never the daily host.

### C4 — detector-bypass variant generation (Phase 3 expansion)

- **Objective:** expand corpus v1.0.0 from 4 families/9 cases to the charter's
  full variant matrix across surfaces with no corpus case
  (`testing/detector-benchmark.md` §6 lists examples: deep-static, nested
  archives, provenance artifacts, bytecode carriers, editor tasks, Cursor/MCP
  configs, AI boundaries, recovery artifacts, updater signatures; no
  surface→case mapping has been established).
- **Component:** all deterministic analyzers (S1, S2, S15, S16 in the attack
  surface inventory).
- **Why necessary:** trigger 2 cannot be evaluated until measurable misses (or
  their absence) exist across representations; 4/4 on nine cases says little.
- **Blue can:** detection-engineering review of every variant. **Blue cannot:**
  — nothing demonstrated.
- **Local models can:** variant generation (Table B, B1) at unknown quality.
- **Observed limitation:** none of any model — **no generation attempt by any
  model has been made or measured.** The only measured facts: 4/4 detection,
  0/4 FN on the current corpus (worker, exit 0).
- **Why Red would materially improve:** `[Speculation]` — this is the strongest
  Red candidate on subject-matter grounds (adversarial-evasion generation is
  offensive tradecraft). A cyber model *might* produce qualitatively better
  evasive representations than Blue/local. That is precisely the claim that
  needs a measured comparison before it can support a Red justification.
- **Safeguards/scope:** inert/defanged fixtures only, `example.invalid`,
  public corpus limitations declared (not a holdout, no prevalence claims).

### C5 — AI evidence-laundering chains (Phase 5)

- **Objective:** run the charter's Phase 5 attack categories through the real
  AI data-flow map (`architecture/trust-boundaries.md` Question 3), with mocked
  or separately approved transports.
- **Component:** `analyzers/ai_static.py`, `core/instruction_guard.py` AI,
  `core/agent.py` proposal path.
- **Why necessary:** S12 is rank 7 of 15 ranked attack surfaces and Phase 5 is
  `NOT EXECUTED`; trigger 4 cannot be evaluated without it. Red's review
  separately concluded no audited AI surface converts model output into
  execution authority (limited scope, gate pending).
- **Blue can:** injection analysis and defensive interpretation (named use).
  **Blue cannot (hypothesized, unmeasured):** author sufficiently *effective*
  adversarial payloads against reduced-refusal models — `[Speculation]`.
- **Local models can:** run as the *target* under test (loopback providers are
  already supported) and draft injections at unknown quality.
- **Observed limitation:** none of any model. No injection campaign has run.
- **Why Red would materially improve:** `[Speculation]` — realistic adversary
  simulation against the project's own AI boundaries is Red's intended use;
  effectiveness unknown.
- **Safeguards/scope:** own components only; mocked transports by default; no
  provider spend; outputs treated as hostile; never persisted as authority.

### C6–C8 — chained simulations, recovery chains, desktop IPC fuzz

- **C6 (Phase 4 chains A/B/C), C7 (A6/R5/R7), C8 (A4):** each is a scripted,
  deterministic, owned-component workflow in a disposable environment (or, for
  C8, against the project's own Electron shell with a simulated renderer).
  Blue/local cover authoring and review; Red adds `[Speculation]` value only in
  creative chain composition. **Observed model limitation: none — nothing
  measured.** Safeguards: per `governance/authorization-scope.md`; C6/C7 need
  the VM round and root-owned fixtures (red NOT EXECUTED list).

## 5. Separation table — refusal vs. technical limitation

| Observation class | Present in this assessment? | Source |
| --- | --- | --- |
| Model refusal encountered | **No — no model was called** | This round's constraints |
| Weak model output observed | **No — no model was called** | This round's constraints |
| Deterministic technical limitation (code behavior demonstrated) | Yes: R1 race (executed), R2 `_contains("/")` fail-closed bug (executed), R6 config-guard lookalike-form gap (executed), R8 silent weak validation (verified by source inspection; caller-disclosure impact NOT EXECUTED) | red report, probes exit 0, gate pending |
| Environment/provisioning limitation (blocks testing, says nothing about models) | Yes: root/VM/disk requirements for R3/R4/R5/R7/R9/R10 and every Phase 2 race | red NOT EXECUTED list; `testing/privilege-boundaries.md` |

## 6. Conclusion of this file

The next phase of the program — validating R3–R10 in a disposable VM,
remediating R1/R2/R6/R8, expanding the detector corpus, and running Phase 5 —
is **fully within Blue, standard, and local-model capability as documented,
and within deterministic tooling that needs no model at all**. Two candidates
(C4, C5) are plausibly improved by Red-grade models, but neither has any
measured evidence of Blue/local insufficiency, and the charter forbids
substituting speculation for that measurement. Therefore **no work item in the
current plan requires Red capabilities**, and the strongest honest claim is:
*Red might improve the quality of adversarial-variant and injection
generation; whether it materially does so is an open, testable question for a
future round with owner-approved model evaluation.*
