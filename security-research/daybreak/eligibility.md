# Daybreak eligibility — current program requirements and AuraScan's position

Assessment date: **2026-11-09** (all web retrievals below were performed
2026-11-09, 08:38–08:44 UTC). Baseline: `02ac13d`, AuraScan 0.15.0, rule
catalogue 1.15.0.

This file records what current authoritative OpenAI documentation says about
Daybreak (formerly "Trusted Access for Cyber") and what AuraScan can and cannot
establish against those requirements. Claims are labelled `[Verified]`,
`[Inference]`, `[Speculation]`, or `[Unverified]` per
`findings/daybreak/PROGRAM-CHARTER.md` §2. Every eligibility requirement below
carries its source URL and retrieval date. Nothing here is an application, an
outreach, or a commitment; no account, plan, or credential state was touched.

**AuraScan is an independently developed open-source project. It is not an
enterprise, is not operating under a formal business or enterprise
organization, and claims no organizational credentials**
(`findings/daybreak/PROGRAM-CHARTER.md` §1, owner statement [Verified]).

## 1. Retrieval log

| # | URL | Retrieved (UTC) | What it establishes here |
| --- | --- | --- | --- |
| 1 | https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview | 2026-11-09 | Program overview; Blue/Red tier table; intended use categories; approval model; individual eligibility summary |
| 2 | https://help.openai.com/en/articles/20001258-trusted-access-for-cyber | 2026-11-09 | Second live variant of the same article ID; reduced-refusals table by model; the "business and enterprise organizations only" Red restriction |
| 3 | https://help.openai.com/en/articles/20001259-openai-daybreak-common-issues-and-troubleshooting | 2026-11-09 | Individual account-security requirements; FIDO2 key rule; API project controls; verification flow |
| 4 | https://help.openai.com/en/articles/20001261-enterprise-daybreak-onboarding | 2026-11-09 | Organization onboarding: intake → Persona KYB → eligibility decision → project setup; "Do not assume Red eligibility from Blue eligibility"; controls initially OFF |
| 5 | https://developers.openai.com/api/docs/guides/daybreak.md | 2026-11-09 | API mechanics (`access_programs.cyber`); per-model approval matrix; Red organizations must require SSO and enforce MFA via IdP |
| 6 | https://openai.com/daybreak/ | 2026-11-09 | Program landing page; apply-as-individual-or-organization; Frontline Defenders registration ("utility, state or local government, community bank, nonprofit, or open-source project"); "Patch the Planet" for open-source maintainers |
| 7 | https://openai.com/index/daybreak-for-frontline-defenders/ | 2026-11-09 | $1B subsidized Daybreak access initiative (published 2026-09-03); named beneficiary classes include open-source projects |
| 8 | https://openai.com/index/expanding-daybreak-as-the-cyber-defense-window-narrows/ | 2026-11-09 | Search-result snippet only (not extracted); corroborates tier purposes and the recommendation that Blue is the starting point. Claims taken from this page are `[Unverified]` unless corroborated by pages 1–7 |
| 9 | https://help.openai.com/en/articles/20001532-openai-daybreak-migration-org-consolidation-guide | 2026-11-09 | Search-result snippet only (not extracted); internal-use-only and no-third-party-extension statements used only where corroborated. `[Unverified]` standalone |
| 10 | https://github.com/crizzler/AuraScan | 2026-11-09 | AuraScan public repository observable state (used for dossier sections 1 and 15) |

Note: the two variants of article 20001258 (rows 1 and 2) are both live and
**disagree** — see §4 gap G4. Where they conflict this file reports both.

## 2. Current program description [Verified — rows 1–5]

- **Daybreak Access is OpenAI's Trusted Access for Cyber program.** Daybreak
  Blue and Daybreak Red are access tiers within it. (rows 1, 2)
- **Intended scope:** "authorized defensive cybersecurity work on systems,
  applications, accounts, networks, or data that you own, operate, or are
  explicitly authorized to test or analyze"; internal use only — "Do not enable
  Daybreak for customer-facing applications, downstream product traffic, or
  third-party access." (row 1)
- **Daybreak Blue** — reduced refusals on supported mainline models (GPT-5.5,
  GPT-5.6 Sol, GPT-6 Sol, GPT-6 Luna; Astra retains standard safeguards in the
  row-1 table); no cyber-specialized models. Intended use cases: "Vulnerability
  triage, secure code review, malware analysis, detection engineering, incident
  response, and patch validation." (rows 1, 2)
- **Daybreak Red** — cyber models (see G4 for the exact current set) plus
  reduced refusals on supported mainline models including Astra and Astra
  Minor. "Requires separate Red approval, stronger verification, and access
  controls." Intended use cases: "Authorized penetration testing, red teaming,
  exploit validation or development, and controlled vulnerability research."
  (rows 1, 2)
- **Approval model:** "Access for Daybreak Blue and Red requires additional
  approval… OpenAI reviews requests before enabling access. Approval is not
  automatic." Review considers "your organization and cybersecurity
  capabilities", the intended defensive workflows, the OpenAI
  organization/workspace to be used, and "verification or trust information
  needed to assess eligibility"; benefits depend on identity/trust
  verification, risk considerations, intended use, and "the applicant's ability
  to strengthen the broader cybersecurity ecosystem". Approved use is bound by
  OpenAI's Cyber Abuse Policy. (rows 1, 4, 9-corroborated)
- **Approval ≠ activation:** "Approval alone does not turn on reduced refusals.
  Daybreak controls are initially OFF." Per-request behavior is selected with
  `access_programs.cyber` (`standard` / `daybreak_blue` / `daybreak_red`),
  matched to the model, within an approved organization and enabled project;
  default API projects are not eligible. (rows 4, 5)

## 3. Eligibility requirements [Verified — rows 1–5]

### 3.1 Individual path (Blue only)

| Requirement | Source (row) | Retrieval date |
| --- | --- | --- |
| At least 18 years old | 1, 2 | 2026-11-09 |
| Eligible paid plan | 3 | 2026-11-09 |
| Advanced Account Security enabled | 3 | 2026-11-09 |
| At least one compatible **physical FIDO2 hardware security key** (software or synced passkeys do not qualify) | 2, 3 | 2026-11-09 |
| Identity verification via the `chatgpt.com/cyber` eligibility flow | 2, 3 | 2026-11-09 |
| Existing individual users must meet the account-security requirements by **Oct 1, 2026** to keep access | 3 | 2026-11-09 |
| **Red is not available through the individual application process:** "Daybreak Red is currently available only to approved business and enterprise organizations… Individuals can apply for Daybreak Blue, but Blue approval doesn't include Daybreak Red." A "some individuals may have access as an exception" caveat exists; the exception is not an application path | 2 | 2026-11-09 |

### 3.2 Organization path (the only documented route to Red)

| Step | Source (row) | Retrieval date |
| --- | --- | --- |
| Submit the enterprise Daybreak intake form | 4 | 2026-11-09 |
| Complete Know Your Business (KYB) verification via Persona | 4 | 2026-11-09 |
| OpenAI internal eligibility and suitability checks; decision names Blue, Red, or both; "Daybreak Red requires separate eligibility. Do not assume Red eligibility from Blue eligibility." | 4 | 2026-11-09 |
| Configure the approved workspace / API organization; Daybreak on non-default projects only | 3, 4 | 2026-11-09 |
| **All Daybreak Red organizations must require SSO for the API organization holding Cyber access and enforce MFA through the identity provider** | 5 | 2026-11-09 |
| Some frontier cyber models need additional model-specific approval even after Red approval (see G4) | 4, 5 | 2026-11-09 |

### 3.3 Possibly relevant programs [Unverified applicability to Red]

- **Daybreak for Frontline Defenders** (row 7, published 2026-09-03): $1B in
  subsidized Daybreak access, training and support; named beneficiaries include
  "open-source maintainers" and "open-source projects" (rows 6, 7). What this
  concretely provides — including whether it changes the Red
  business/enterprise restriction — is `[Unverified]`.
- **Patch the Planet** (row 6): helps open-source maintainers "validate
  findings, test patches and coordinate disclosure" (with Trail of Bits, Calif,
  HackerOne). It is described as validation/disclosure support, not as model
  access; details `[Unverified]`.
- **Daybreak Partner Program** (rows 1, 2): for externally facing workflows —
  not applicable to AuraScan's internal research; noted for completeness.

## 4. Explicit gaps — eligibility questions this assessment could not verify

| ID | Gap | Status |
| --- | --- | --- |
| G1 | Whether an independent developer without a formal business/enterprise organization can satisfy the "approved business and enterprise organizations" condition for Red (e.g. via a sole proprietorship or similar entity). No authoritative source retrieved addresses non-enterprise organizations | `[Unverified]` |
| G2 | The full Red eligibility/suitability criteria beyond the public summaries (legal attestations, monitoring terms, contractual commitments, pricing). The help pages describe the review but do not publish the rubric | `[Unverified]` |
| G3 | Whether Daybreak for Frontline Defenders or Patch the Planet alters Red eligibility for open-source projects, or substitutes for any organization requirement | `[Unverified]` |
| G4 | Which cyber-model approval set is current for Red: the row-2 variant of article 20001258 says "GPT-5.6 Cyber for all Daybreak Red organizations, GPT-6 Cyber with separate model approval, GPT-5.5-Cyber for organizations with existing access", while the row-1/row-2 reduced-refusals table, row 4, and row 5 say **GPT-5.6-Cyber requires Red *plus* additional model approval**. Both variants are live on 2026-11-09. This assessment treats the stricter reading as operative | `[Unverified]` — conflicting authoritative sources |
| G5 | The maintainer's individual account state (paid plan, Advanced Account Security, FIDO2 hardware key, identity-verification status). Private account facts; not established and not checked | `[Unverified]` |
| G6 | Whether the maintainer has or could satisfy SSO + IdP-enforced MFA for an API organization (a Red requirement). AuraScan's development environment has no such infrastructure on record | `[Unverified]` |
| G7 | Absolute last-update timestamps of the help articles (pages render "Updated: yesterday" without an absolute date; retrieval date stands in) | `[Unverified]` |
| G8 | Whether any exception path ("some individuals may have access as an exception") is accessible, and on what criteria | `[Unverified]` |

## 5. What AuraScan can establish [Verified]

1. **Project identity and ownership of the source.** Public repository
   `https://github.com/crizzler/AuraScan`, MIT license, default branch `main`,
   created 2026-07-07, 181 commits observed 2026-11-09 (row 10). An AUR
   package `aurascan` is referenced from the README (row 10).
2. **Organizational status.** Developed independently; **not** operating under
   a formal business or enterprise organization (charter §1). No enterprise or
   organizational credential is claimed anywhere in this program.
3. **Authorized research scope.** A written authorization scope exists:
   `security-research/governance/authorization-scope.md` — testing confined to
   the AuraScan repository, inert fixtures, disposable VMs/containers,
   controlled recovery images, and maintainer-owned environments; third-party
   targeting prohibited; fresh owner approval per elevated/destructive test.
4. **Safeguards.** Binding safety invariants in `AGENTS.md` (never execute
   untrusted package code; fail-closed defaults; AI opt-in and raise-only;
   inert defanged fixtures; bounded hostile-input tools); the measured
   architecture (135 modules, 87,315 lines, 19 invariants, 0 violations —
   `tools/architecture_audit.py --strict`, exit 0, 2026-11-09).
5. **Disclosure posture.** `security-research/governance/responsible-disclosure.md`
   and `vulnerability-handling.md`: owner-decided disclosure, no automatic
   publication of exploit detail, private evidence tree, remediation before
   publicity, finding-ID lifecycle. No external disclosure has been made or is
   authorized.

## 6. What AuraScan cannot establish [Unverified / not applicable]

- Any business/enterprise organization, KYB-verifiable entity, tax/registration
  identity, or org admin structure — none exists on record (G1).
- Identity-verification outcome, plan status, or hardware-key status for the
  maintainer (G5) — private account facts, out of scope and unchecked.
- SSO/IdP-enforced MFA capability for an API organization (G6).
- Adoption, deployment, download, or incident metrics — see
  `application-dossier.md` §15. **Unknown adoption is not zero adoption.**
- Any statement about what OpenAI *would* decide; approval is discretionary
  (row 1) and no application was or may be submitted from this program
  (`ORCHESTRATOR-BRIEF.md` hard constraints).

## 7. Bottom line

On the documentation retrieved 2026-11-09, **Daybreak Red is not reachable
through the individual application path, and AuraScan has no business or
enterprise organization to put through KYB** (G1). Even if eligibility were
satisfied, Red's requirements (separate approval, SSO/MFA, stronger
verification, access controls) are unmet and mostly unmeetable on current
facts. Whether Red is *technically needed at all* is answered separately in
`blue-vs-red.md` and `readiness-assessment.md` — the two questions are kept
independent, as the charter requires.
