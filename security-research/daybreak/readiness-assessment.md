# Readiness assessment — Daybreak Red

Assessment date: 2026-11-09 (UTC). Baseline: `02ac13d`, AuraScan 0.15.0,
rule catalogue 1.15.0. Assessor: `architect` (Daybreak assessment card
`t_3f5a5f54`). Evidence base: baseline architecture package (`t_c667ed14`),
red adversarial review (`t_41563ead`, gate pending), worker evidence harness
(`t_1503aa02`), and OpenAI documentation retrieved 2026-11-09 (URLs in
`eligibility.md` §1).

---

## Verdict: **NOT READY**

**Answer to the card's question:** there is now a real, evidence-backed
security research *program* — four confirmed boundary weaknesses (R1, R2, R6
executed; R8 verified by source inspection, caller-disclosure impact NOT
EXECUTED; reviewer gate pending) and six inference-level candidates
(R3–R10) — but **no research need that requires Red capabilities. Blue,
standard, and local models, plus deterministic harnesses that need no model at
all, are sufficient for the next phase.** Separately, Red would not be
attainable on current facts even if it were needed: it is currently available
only to approved business and enterprise organizations
(help.openai.com/en/articles/20001258, retrieved 2026-11-09), and AuraScan is
an independent project with no such organization.

## Reasons

1. **No demonstrated need for Red capabilities.** The next phase (validate
   R3–R10 in a disposable VM, remediate R1/R2/R6/R8, expand the detector
   corpus, run Phase 5) maps to Blue's documented intended use or to
   model-independent deterministic engineering (`blue-vs-red.md` §1–2). The
   charter requires that a Red justification rest on demonstrated
   insufficiency of existing tools — none exists.
2. **No model evidence exists in either direction.** No live model calls were
   permitted this round; zero refusals and zero weak outputs are in the
   evidence base. Every "Red would help" claim is `[Speculation]`
   (`blue-vs-red.md` §5). The charter forbids manufacturing certainty here.
3. **Eligibility is not satisfied and is not satisfiable on current facts.**
   Red is organization-only (business/enterprise, KYB, SSO+MFA via IdP,
   separate approval); AuraScan is explicitly not an enterprise
   (`eligibility.md` §3–4). A vulnerability must never be left unfixed to
   strengthen an application, and an application must not precede eligibility.
4. **The evidence round itself is mid-flight.** The reviewer gate (`t_32ee3ab1`)
   has not yet verified the round's findings, and every privilege-boundary
   test requiring a real adversary process, root, or a VM is `NOT EXECUTED`.
   Recommending application preparation over an ungated, incomplete baseline
   would be premature by the charter's own standard.

## Five trigger categories (charter §10)

| # | Trigger | Status | Evidence | Exact missing evidence |
| --- | --- | --- | --- | --- |
| 1 | Privilege-boundary testing: reproducible test shows a genuine boundary weakness **or** a credible need for deeper exploit validation | **MET in its first branch** (subject to reviewer gate) — genuine boundary weaknesses demonstrated: R1 containment race reproduced by executed probe (outside-root bytes through the capped read, exit 0); R2, R6 confirmed by executed probes (red `t_41563ead`, 2026-11-09); R8 verified by source inspection, caller-disclosure impact NOT EXECUTED | Second branch untested: R3/R4/R5/R7/R9/R10 validations `NOT EXECUTED`; independent reviewer verification pending (`t_32ee3ab1`); "deeper exploit validation" has not been shown to exceed Blue/local/deterministic capability |
| 2 | Versioned detector-bypass benchmark shows measurable misses of security-relevant behavior | **NOT MET** | Corpus v1.0.0: 4/4 detection, 0/4 FN, 0/1 FP per family (executed, exit 0) — no misses measured; no corpus case exists for several surfaces and no surface→case mapping has been established (coverage gaps are not misses) | A larger versioned corpus with measured false negatives across the charter's variant matrix (`blue-vs-red.md` C4) |
| 3 | Multi-component exploit chain weakness | **NOT MET** | Phase 4 chains A/B/C `NOT EXECUTED` | Executed chained simulations in a disposable VM; the closest candidate (R3, a scan→install mismatch spanning sandbox + wrapper) is `[Inference]` only |
| 4 | AI-mediated security failure affecting a security decision or trust boundary | **NOT MET** | Phase 5 `NOT EXECUTED`; red's static review found no AI surface converting model output into execution authority (scope-limited) | An executed injection/laundering campaign with mocked transports (`blue-vs-red.md` C5) |
| 5 | External exposure (adoption, external reports, malicious contributions, attacker attention) | **UNKNOWN — not met** | Public observables only (repo created 2026-07-07, 181 commits, AUR package; observed 2026-11-09); stars/downloads/reports `[Unverified]` | Verified exposure evidence. **Unknown adoption is not zero adoption** |

**A met trigger is not a Red requirement.** Trigger 1's met branch is the
charter's signal to *evaluate* (novelty, evidence quality, severity,
exploitability, mitigations, relevance to Red, whether existing tools remain
sufficient, whether eligibility is satisfied). On that evaluation: severity of
R1 is bounded (information disclosure, read-only tools); remediation is
ordinary engineering; existing tools remain sufficient for validation and
fix-verification; eligibility is not satisfied. The trigger therefore does not
move the verdict.

## Options considered

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **NOT READY** (chosen) | No measured Blue/local insufficiency; Red eligibility hard-fails; work plan is deterministic; charter warns against inferring need from product category | Trigger 1 has a met branch — a purely trigger-driven reader might expect movement | **Selected** — it is the only class consistent with the evidence contract |
| PREPARE | Four confirmed findings justify a controlled-vulnerability-research story; exploit validation is Red's exact intended use | PREPARE asserts a credible technical justification *for Red*; none is established — the justification is for the research program, which existing tools serve. Would upgrade on `[Speculation]` (C4/C5), which the charter forbids | Rejected |
| APPLY WHEN ELIGIBLE | — | Eligibility not satisfied; no Red-necessity evidence. Rejected on both prongs | Rejected |
| URGENT SECURITY RESPONSE | — | No serious vulnerability requiring immediate remediation regardless of Daybreak: R1 is read-only disclosure (fix proposed to owner, ordinary timeline); R2 is fail-closed; R6 needs a hostile-config precondition; R8 is evidence-quality. None meets "serious vulnerability requires immediate remediation" | Rejected; if the reviewer gate or owner escalates any finding, this class takes precedence and pauses application work |

## What would change my mind

Any one of: (1) a measured, owner-approved model comparison in which Blue and
local models **fail to produce a required exploit-validation or
adversarial-generation artifact** that a Red-class capability produces
(a measured failure, never a refusal); (2) a confirmed finding whose
exploit-chain validation demonstrably exceeds disposable-VM deterministic
testing; (3) the maintainer establishing an eligible business/enterprise
organization (KYB, SSO/MFA) **and** item (1) or (2) — eligibility alone moves
nothing; (4) verified trigger-5 exposure or an `URGENT SECURITY RESPONSE`
finding, which would reframe the whole assessment.

## Recommendation to the maintainer

Continue ordinary development and the evidence program with Blue, standard and
local models: run the Phase 2 disposable-VM round (R3/R4/R9/R10 and the A1–A10
assumption tests), let the reviewer gate `t_32ee3ab1` verify this round,
expand the corpus toward trigger 2, and re-assess on material new evidence.
Do not apply, do not create accounts, and do not contact OpenAI from this
program — that decision and any outreach remain the owner's alone
(`governance/responsible-disclosure.md`, `ORCHESTRATOR-BRIEF.md`).
