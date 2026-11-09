# Responsible disclosure — Daybreak evidence program

Baseline: `02ac13d`. Companion files: `vulnerability-handling.md` (finding
lifecycle) and `authorization-scope.md` (testing scope).

## Principles

1. **The owner decides disclosure.** Every disclosure decision — timing,
   channel, content, coordination with any upstream — is the project
   maintainer's. Research roles prepare evidence and recommendations; they do
   not publish, contact third parties, or file external reports on their own.
2. **No automatic publication of exploit detail.** Working exploit artifacts,
   step-by-step exploitation guides, and raw vulnerable payloads are never
   published automatically and never committed to the public repository.
3. **Remediation before publicity.** If a serious vulnerability is found,
   responsible remediation takes priority over any application or benchmark
   goal (`PROGRAM-CHARTER.md` §15). A vulnerability is never left unfixed to
   strengthen an application.

## Private evidence handling

- Sensitive exploit details, non-public vulnerability evidence, raw adversarial
  output, and candidate-vulnerability records live in a private,
  access-controlled location **outside the public repository**
  (`<private evidence root>` in this program).
- Private evidence is referenced from public documents by **evidence ID only**
  (e.g. `PRIV-DB-0003`), never by content.
- No real credentials, API keys, tokens, private paths, or personal data enter
  either tree. Fixtures stay inert (`example.invalid`, synthetic credentials,
  temporary roots) per `AGENTS.md`.
- Evidence artifacts are hashed (SHA-256) so later integrity disputes are
  decidable; access to the private tree is limited to the maintainer and the
  roles explicitly granted access.

## Sanitized public summaries

Public documents (`security-research/**`) may contain:

- the nature of a finding at a level that helps defenders and users;
- affected component and version range;
- the classification and status (`confirmed` / `proposed` / `retested`);
- remediation status once released;
- references to private evidence IDs.

Public documents must **not** contain:

- exploit code, payloads, or reproductions that materially aid an attacker
  before a fix is available;
- raw scanner evidence containing secret-adjacent bytes;
- claims that exceed the evidence (a static match is not execution; a passing
  test is not safety).

A finding that is already public (e.g. a shipped regression everyone can
observe) may be described more directly, but still without weaponizable
detail.

## Disclosure decision point

When a finding is confirmed, the researcher hands the maintainer:

1. the finding record (`vulnerability-handling.md` fields),
2. a proposed remediation,
3. a draft sanitized public summary,
4. a recommendation on disclosure timing (with the trigger analysis if this
   affects the Daybreak assessment).

Then the flow stops at the owner: **publish, coordinate, or withhold is the
maintainer's call**, recorded with a date. If the maintainer chooses
withholding, the reason is recorded in the private evidence so a later
assessment can weigh it; withholding never reclassifies a finding as
non-finding. Urgent security responses (decision class
`URGENT SECURITY RESPONSE`) may compress the timing but never skip the
owner's decision.

## External contact

No outreach, submission, or external contact happens without explicit owner
authorization — including Daybreak applications, upstream project
notifications, and registry abuse reports.
