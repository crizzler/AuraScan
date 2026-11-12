# Daybreak application dossier — skeleton, populated with verified facts only

Assessment date: 2026-11-09. Baseline: `02ac13d`, AuraScan 0.15.0, rule
catalogue 1.15.0. Structure: `PROGRAM-CHARTER.md` §11 (17 sections).

This is a **living evidence package, not an application**. It is populated only
with verified facts and explicit gaps. Sections that cannot honestly be filled
are marked `NOT READY` or `[Unverified]`; nothing is invented. AuraScan is an
independent open-source project and is **not** described as an enterprise
anywhere in this dossier.

Evidence labels: `[Verified]`, `[Inference]`, `[Speculation]`, `[Unverified]`
(charter §2). Red-role findings are cited as reported by task `t_41563ead`
(2026-11-09) with the independent reviewer gate `t_32ee3ab1` **pending**.

## 1. Project identity and purpose

[Verified] AuraScan — static-first safety layer for Arch-family package and
maintenance workflows (PKGBUILD/install-hook review, bounded package-archive
inspection, upgrade preflight, guarded incident and recovery workflows,
opt-in Agent Instruction Guard, opt-in advisory AI). Public repository:
`https://github.com/crizzler/AuraScan` (MIT, default branch `main`, created
2026-07-07, 181 commits observed 2026-11-09). AUR package `aurascan` is
referenced from the README. Baseline revision `02ac13d`; version `0.15.0`
(`pyproject.toml:7`); rule catalogue `1.15.0` (`aurascan/core/engine.py:108`).

## 2. Maintainer and organizational status

[Verified] Developed independently by the project maintainer ("crizzler");
**not operating under a formal business or enterprise organization**
(`findings/daybreak/PROGRAM-CHARTER.md` §1). Single-maintainer governance: the
owner authorizes testing scope, disclosure, and fixes
(`governance/authorization-scope.md`, `governance/responsible-disclosure.md`).
No organizational credentials, KYB identity, tax/registration status, staff,
or security team are claimed — none exist on record. Contributor identity
beyond the public Git history is `[Unverified]` and out of scope.

## 3. System architecture

[Verified] Measured at baseline: 135 modules, 87,315 physical lines, 19
architecture invariants, 0 violations (`python tools/architecture_audit.py
--strict`, exit 0, 2026-11-09). Full trust model with `path:line` evidence:
`security-research/architecture/trust-boundaries.md` (15 boundaries B1–B15,
8 privilege transitions T1–T8, 4 named questions) and
`trust-boundaries.mmd`. Capability matrix (identity, filesystem/network
access, execution authority, consent per component):
`architecture/capability-matrix.md`. Test baseline: 5,714 passed / 3 skipped
under `PATH=/usr/bin:/bin` (2026-11-09; the default-PATH 33 failures are
environment artifacts, documented in `security-research/README.md`).

## 4. Security-sensitive capabilities

[Verified, from `architecture/capability-matrix.md`] Execution authority lives
in: the makepkg wrapper handoff (executes package build logic, consented);
the opt-in devtools build sandbox (`AURASCAN_AUR_SANDBOX=devtools`);
sudo/pacman upgrade and incident/repo repair paths; recovery `arch-chroot`
execution as recovery root; the Repair Agent's fail-closed allowlisted command
execution (fresh per-command confirmation, SHA-256 command binding); the
privileged intelligence-verify/install step; two bounded MCP subprocess call
sites; desktop main spawning only `/usr/bin/aurascan` with fixed argv. The
pacman hook mode runs the scanner inside the root transaction (`AbortOnFail`).
Trusted system tools (`/usr/bin/makepkg`, `/usr/bin/sudo`, `/usr/bin/pacman`,
`git`/`gpg`/`bsdtar`/`clamscan`, …) are identity-captured and revalidated —
explicitly "a trust check, not a sandbox" (`core/trusted_executable.py:24-27`).

## 5. Authorized research scope

[Verified] `governance/authorization-scope.md`: testing confined to the
AuraScan repository and local copies, purpose-built inert fixtures, disposable
VMs/containers, controlled recovery images/simulated targets, and
maintainer-authorized environments. Prohibited: third-party targeting,
executing malicious fixtures on the workstation, `makepkg`/sudo/package
install/recovery actions in this round, host privilege exploits, fabricating
results, live provider calls, applying fixes without owner authorization.
Elevated/destructive tests require **fresh owner approval per test**, run only
in disposable environments.

## 6. Existing defensive controls

[Verified] Bounded literal-only parsing with fail-closed gaps (malformed
arrays, dynamic mutation, sourcing/eval all block); mandatory install-hook
evidence with no-follow double capture; bounded no-follow archive reading with
incomplete-capture-is-coverage semantics; always-on repository-provenance walk
(no Git/native tools); makepkg handoff recapture + `sudo -k` + post-build
`.INSTALL` byte comparison; identity revalidation of trusted tools; typed
confirmation phrases for recovery actions; machine-and-UID-bound approvals;
AI raise-only with strict duplicate-key-rejecting validators and no
tool/URL/command authority; loopback-only local AI providers; redaction and
bounded outputs everywhere; consent gates on every privileged transition
(`architecture/trust-boundaries.md` B1–B15).

## 7. Threat model

[Verified/Inference per `architecture/attack-surface-inventory.md`] Adversary:
a malicious package/AUR author, hostile feed or acquired-source content, a
same-UID local process, a compromised recovery target, or hostile model
output. 15 ranked attack surfaces; S6 is described but not ranked (R×A×I×G
with stated limits of the method);
top surfaces: package control text (S1, 200), makepkg wrapper handoff (S5,
180), package archives/`.INSTALL` (S3, 128). 10 ranked open assumptions
A1–A10 for later adversarial tests. Standing limits: boundaries are risk
reduction, not sandboxes; same-UID and root-level compromise are out of scope
of any single boundary; a passing test is not proof of safety.

## 8. Reproducible adversarial test cases

Partially populated. [Verified, executed] (red role `t_41563ead`, inert
unprivileged probes, exit 0): L1 `read_capped` containment/open race
(symlink swap after resolution returned outside-root bytes through the capped
read); `_contains("/")` fail-closed rejection; user `makepkg.conf` guard
misses `declare`/`readonly`/`typeset`/`local` forms. [Verified by source
inspection; caller-disclosure impact NOT EXECUTED] (red role `t_41563ead`):
`validate_recovery_image` silent weak-validation path. [Verified, executed]
(worker role `t_1503aa02`): detector corpus v1.0.0 — 9 inert cases in 4
families with benign controls and an INCOMPLETE coverage case, each with a
reproduction command (`testing/detector-benchmark.md` §7); unit probe log with
literal outputs (`evidence/test-results/2026-11-09-baseline.md`).
`NOT EXECUTED`: every race requiring a real racing adversary, cross-process
capability replay, root/chroot legs (R3/R4/R10), sudo-timestamp window (R9),
compromised recovery targets, USB/boot paths — provisioning notes recorded in
the red report and `testing/privilege-boundaries.md`. Full detail belongs to
`testing/` and `evidence/` (worker-owned).

## 9. Confirmed security findings

[Verified by red-role executed probes (R1, R2, R6) and source inspection (R8);
reviewer gate pending]
- **R1** — MCP `read_capped` containment/open race (matches the recorded L1
  open candidate, `docs/ARCHITECTURE.md:222`): information disclosure across a
  documented containment promise; no write/execution. Reproduced by probe.
- **R2** — `_contains` rejects every path when the configured root resolves to
  `/`: fail-closed availability bug at a guard boundary (not an escape).
- **R6** — user `makepkg.conf` guard misses shell-lexical declaration forms
  (`declare`/`readonly`/`typeset`/`local`): guard bypass potential for
  PACMAN/DLAGENTS/VCSCLIENTS redirection (probe confirmed the guard gap; the
  makepkg-sourcing consequence is `[Inference]`).
- **R8** — `validate_recovery_image` silently applies a weaker check when
  `ukify` is absent, indistinguishable in the return value (verified by source
  inspection; caller-disclosure impact NOT EXECUTED). **Remediation released
  in 0.17.0:** validation fails closed when `ukify` is unavailable, and the
  recovery-bearing 0.17.0 ISO and validation UKI passed the BIOS, UEFI and
  disposable-key Secure Boot gates.

[Inference — needs validation] R3 (sandbox artifact scan→install not
re-bound), R4 (`sudo cp -a` to a user-writable `build_root/root`), and R9
(sudo timestamp re-arm window) remain open. R5 (`snapshot_id` unvalidated —
latent), R7 (bare-name PATH tools in recovery steps), and R10 (cleanup
`sudo rm -rf` without identity revalidation) are remediated in 0.18.0:
R5 uses a total canonical-ASCII snapshot-id validator before path or argv use;
R7 captures every recovery host tool at its fixed `/usr/bin/<name>` identity
and revalidates immediately before use; R10 cleanup reuses the captured
`sudo`/`rm` identities and requires a zero status plus an observed-absent tree.
The 0.18.0 recovery-bearing ISO and validation UKI passed the BIOS, UEFI and
disposable-key Secure Boot gates, but booted target-disk repair scenarios and
the two unchanged transport residuals remain unverified. Per
`governance/vulnerability-handling.md`, no finding is described as
exploitability or compromise; none was manufactured.

## 10. Benchmark results

[Verified, executed 2026-11-09] Corpus `1.0.0` (public-synthetic, exposed,
not a holdout): detection rate **4/4** malicious-intent cases; false-negative
rate **0/4** (fixture-bounded only); false-positive rate **0/1 per family**
(tripwire); regression rate **not measured** (no predecessor run); coverage of
new surfaces **not measured** — no corpus case exists for several surfaces
(examples: deep-static, nested archives, provenance artifacts, bytecode
carriers, editor tasks, Cursor/MCP configs, AI boundaries, recovery artifacts,
updater signatures); no surface→case mapping has been established. Claim
limits: no prevalence, no independence, no safety claim
(`testing/detector-benchmark.md` §1). Full-suite regression: 5,714 passed /
3 skipped at baseline.

## 11. Blue/local-model limitations

`NOT READY` — **no model evaluation has been run.** No live model calls are
authorized this round; no model refusal and no weak output exists in the
evidence base. Per charter §9 no refusal-based argument is admissible anyway.
The only honest statement: on documented intended use (help.openai.com
20001258, retrieved 2026-11-09) Blue covers vulnerability triage, secure code
review, malware analysis, detection engineering, incident response and patch
validation; the next phase's work falls in those categories or is
model-independent deterministic harnessing (`blue-vs-red.md` §1–2). Whether
Blue/local models produce sufficiently high-quality adversarial variants or
injection payloads is `[Unverified]` and testable — see
`blue-vs-red.md` §4 C4/C5.

## 12. Specific justification for Red

`NOT READY` — **no evidence-backed research need requires Red capabilities.**
The work matching Red's intended use (exploit validation, exploit-chain
validation, controlled vulnerability research) exists in candidate form
(`red-use-cases.md`), but each candidate's required artifact is producible by
deterministic harnesses plus Blue/local review on current evidence; the two
candidates with plausible Red value (detector-bypass variant generation, AI
evidence-laundering) rest on `[Speculation]` and unmeasured model capability.
No measured Blue/local insufficiency exists anywhere in the baseline.

## 13. Testing safeguards

[Verified] Isolation model (`security-research/README.md`): workstation =
read-only/inert only; disposable container = inert-to-moderate fixtures;
disposable VM = privilege-boundary and hostile-fixture work; external lab =
owner approval only. Inert-fixture invariants (`AGENTS.md`):
`example.invalid`, synthetic credentials, temporary roots, no working attacker
infrastructure. Fresh owner approval per elevated/destructive test
(`governance/authorization-scope.md`). Never-executed-on-host list enforced
this round (no `makepkg`, sudo, package install, fixture execution, recovery
actions, network scans). Evidence binding: git SHA, version, rule version,
fixture SHA-256, environment, exact command + exit code.

## 14. Vulnerability disclosure policy

[Verified] `governance/responsible-disclosure.md` +
`governance/vulnerability-handling.md`: owner-decides-disclosure; no automatic
publication of exploit detail; private evidence tree outside the repository
(`<private evidence root>`), public references by ID only;
remediation before publicity; a vulnerability is never left unfixed to
strengthen an application; stable finding IDs (DB-YYYY-NNN), severity and
confidence recorded separately, mandatory retest status. External contact
(including any Daybreak application) requires explicit owner authorization.
No external disclosures or reports exist on record
(`[Unverified]` — absence of record, not verified absence).

## 15. Adoption and exposure evidence

[Verified, observed 2026-11-09 on the public repository] Created 2026-07-07;
181 commits; MIT license; AUR package `aurascan` referenced from the README;
public release documentation exists under `docs/releases/`. **Stars, forks,
download/install counts, and external reports were not recorded this round —
all `[Unverified]`. Unknown adoption is not zero adoption, and no active
installations are inferred from anything here** (charter §12). No verified
external vulnerability reports, malicious contribution attempts, or attacker
attention are on record (`[Unverified]` — absence of record). Trigger 5
therefore cannot be evaluated as met.

## 16. Outstanding eligibility requirements

From `eligibility.md` §4 (all `[Unverified]`, none satisfied or satisfiable on
current facts): G1 route for an independent developer to the Red
business/enterprise requirement; G2 full Red criteria/legal terms; G3 whether
Frontline Defenders / Patch the Planet change Red eligibility for open-source
projects; G4 conflicting authoritative statements on the GPT-5.6-Cyber
approval set; G5 maintainer account state (paid plan, Advanced Account
Security, FIDO2 key, identity verification); G6 SSO + IdP-enforced MFA
capability for an API organization; G7 absolute help-article update dates; G8
the individual-exception path. Additionally: no measured Blue/local
limitation exists to justify Red technically (§11–12).

## 17. Application readiness recommendation

**NOT READY.** Full reasoning, trigger table, and change conditions in
`readiness-assessment.md`. Summary: (a) no research need requiring Red
capabilities is established; (b) Red eligibility is not satisfied (individual
developer; Red is currently organization-only — help.openai.com 20001258,
retrieved 2026-11-09); (c) the program's own evidence round is still in
progress (reviewer gate pending; Phase 2 VM round unexecuted). Recommended
action: continue ordinary development and the evidence program with Blue,
standard and local models; re-assess after the Phase 2/3/5 rounds or a
measured model comparison.
