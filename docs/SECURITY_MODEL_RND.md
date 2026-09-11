# Security intelligence and model research

Status: development contract, offline metadata validation and explicit private
[candidate intake](SECURITY_DATA_INTAKE.md). This is not a
product roadmap commitment, a trained model, a hosted service, or a new runtime
analysis mode. [The data contract](../security-data/README.md) describes the
offline manifest validator; the evaluation-run contract below is a design for
future tooling, not an implemented evaluator.

AuraScan should make useful evasion progressively harder by combining validated
security knowledge, deterministic detection, independent evidence, and measured
adversarial evaluation. Its durable value should accumulate in reviewed data,
evaluation history, domain expertise, and eventually specialized models rather
than depend on one foundation model. No combination establishes 100% safety.
Increasing assurance requires reporting what was checked, what remains unknown,
and which evidence layers are actually independent.

## Existing architecture and integration points

The groundwork follows a review of the repository's scanner, provider,
Instruction Guard, incident/recovery/repair, maintenance, fixture, packaging,
and release contracts at application version 0.10.6. This architecture review
is not a line-by-line security audit or evidence that any package is safe.

| Existing surface | Reuse for future research | Boundary to retain |
| --- | --- | --- |
| `core/models.py`, `core/engine.py`, `core/risk.py`, analyzers and rule catalog | Rule IDs, phases, evidence quality, coverage and policy outcomes | An allow decision or absent finding is not benign ground truth; AI cannot clear a deterministic blocker. |
| Package-input, repository and acquired-source snapshots | Bind captured input bytes, revisions and incomplete statuses | A path, cached result or declared checksum alone does not identify everything inspected. |
| `core/ai_provider.py` | Explicit provider/model configuration and injected transport | Existing consent and bounded transport; local endpoints remain loopback-only with proxies disabled, all provider redirects stay disabled, and local failures never fall back to cloud. |
| `analyzers/ai_static.py` and `core/text_safety.py` | Bounded prompt construction and strict response validation | Model responses are hostile data; rejected raw prose/errors remain discarded. |
| `core/instruction_guard.py`, CLI and tray | Temporary-root scans, injected reviewers, opaque evidence and transactional state | Content risk, integrity approval and coverage remain distinct; the monitor stays network-isolated. |
| Incident/recovery/follow-up planners and deterministic repair catalogs | Mocked probes, plan eligibility, refusal and rollback evaluations | Known local IDs, fresh preconditions and consent govern actions, not model prose. |
| `core/agent.py` | Offline validation of inert proposed command strings | Command-enabled profiles retain the deterministic allowlist and fresh consent for each exact command. Do not invoke execution APIs for research examples. |
| Curated fixtures, archive generators and pytest harnesses | Existing deterministic regression inputs and assertions | Public expected results are development evidence, not secret benchmarks or historical proof. |
| `tools/aur_warning_tune.py` | Explicit metadata-only warning-volume observations | Live sampling is not normal CI, a benign dataset, or a safety certification. |
| Recovery build/boot/privacy gates and release contracts | Independently attested candidate/artifact validation | Research results do not grant release, signing, repair or privileged execution authority. |

Paths above are relative to `aurascan/` except `tools/` and fixture references.
Keep research metadata under the separate `security-data/` contract, outside
packaged `aurascan/assets/`. Existing advisory snapshots remain reviewed
production intelligence. Existing caches, scan reports, incident contexts,
Instruction Guard manifests and provider logs remain operational private state.
They are not automatic corpus inputs, even when a serializer calls its output
"public" or redaction has already been applied.

No new provider abstraction is needed now. Future adapters should reuse
`AIProviderConfig`, explicit model identifiers and injected transports where
appropriate. Compatibility with an OpenAI-style local HTTP API concerns wire
format only; it does not grant tools, network destinations, privileges, privacy
assurances, or permission to redistribute a model's service.

## Research roles and production authority

Future explicitly authorized experiments may assign models as defensive
analysts, adversarial analysts, independent critics, synthetic-example
generators, or teachers for smaller specialized models. Record role separately
from provider, checkpoint and runtime. No named family is the architecture's
default or a promise of future compatibility. Large local models and smaller
fine-tunes are candidates to evaluate, not implicit upgrades.

Research tasks must remain isolated from user credentials, release keys,
publication authority and privileged production execution. A model may propose
an attack hypothesis, inert example or repair explanation. It cannot authorize
sample execution, change deterministic policy, fetch arbitrary resources,
approve integrity baselines, or operate a release pipeline. Future separately
authorized Blue/Red-style research can consume these contracts in an isolated
research environment; it must not add offensive execution to AuraScan.

Keep the production guarantees unchanged: AI is separately opt-in and advisory;
unknown or incomplete inspection fails conservatively; outputs have exact
bounded schemas; malicious fixtures are inert; default scanning does not fetch;
and existing privilege/consent checks stay deterministic. A research experiment
does not opt users into another provider, model, data use or execution profile.

## Corpus taxonomy

Taxonomy describes an item's role; origin, claim, validation and eligibility
are independent metadata. An item can have several roles. A fixture's current
`category` or a model's label cannot establish historical maliciousness.

| Category | Meaning and admission caution |
| --- | --- |
| Publicly sourced benign example | Public input with independently reviewed, bounded benign behavior. Registry availability, popularity or a zero-finding result is insufficient. |
| Verified historical malicious example | Source-attributed historical maliciousness with a reviewed evidence basis. Prefer hashes and defanged derivatives; do not execute or casually redistribute original payloads. |
| Real advisory or incident | A report about affected versions, behavior or an incident. Distinguish the source's claim, independent verification and the date checked. |
| Synthetic adversarial variant | A constructed example, including model output; retain generator identity and lineage. It is not production intelligence by default. |
| Detector-bypass attempt | A hypothesis or tested failure against an exact detector/input configuration. Record unsuccessful attempts as well as supported misses. |
| False-positive example | A reviewed mismatch between a finding and the behavior actually supported by evidence. Keep the disputed claim and adjudication. |
| Remediation or fix example | A bounded repair proposal or code correction with prerequisites and validation. A passing mock test is not a live successful repair. |
| Model disagreement example | Independent judgments about the same permitted evidence, followed by explicit adjudication or unresolved status. Consensus is not proof. |
| Regression fixture | A public, inert development assertion tied to a test and revision. It is exposed material and cannot become a private holdout by renaming it. |
| Private held-out evaluation example | An access-controlled, reserved evaluation item and its lineage. Keep it outside the public worktree and permanently out of training. |

Origin must distinguish real, synthetic, mutated and inferred material. A
mutation derived from a real campaign is still a mutation. Preserve its parents
and campaign/derivation family; do not relabel it as the original payload.

## Admission, evidence and rights

Every future corpus item needs a stable opaque ID, source/provenance references,
collection date, relevant source revision, exact artifact hashes or an explicit
metadata-only identity, origin and lineage, taxonomy, classification and claim
scope. Preserve verified versus suspected behavior, review basis, relevant
AuraScan version, expected outcome, observations of detection/non-detection,
rules or models involved, and missing coverage. Record training eligibility and
evaluation eligibility separately from both collection and analysis permission.
The versioned manifest in `security-data/README.md` makes a small subset of these
admission and separation rules mechanically checkable without collecting data.

Keep these claims distinct:

| Claim | Necessary evidence | What it does not establish |
| --- | --- | --- |
| Suspicious behavior | Captured input and a bounded static correlation | Successful execution or malicious intent. |
| Detector bypass | A validated expected detection or policy boundary, exact input, actual detector result and coverage/configuration | Exploitability or compromise. Correctly blocked incomplete analysis is coverage, while an evidenced fail-open policy error can be a bypass. |
| Exploitability | Separately reviewed evidence that the claimed conditions permit the effect | Execution on a user's host. This task adds no execution workflow. |
| Actual compromise | Independently verified incident evidence with its own provenance | That every installation or similar static match is compromised. |

Do not silently use customer or user scans for training, evaluation or research.
Consent to a scan, provider request, local history or diagnostic retention is
not corpus consent. Any future donation/export requires a separate, specific,
revocable data-use process and minimization review before ingestion. Do not
build that process implicitly into existing reports or background services.

Never train on secrets, credentials, private filesystem paths or unnecessarily
identifiable information. Do not copy such material into corpus metadata either.
Use bounded opaque references and reviewed behavior labels. Hashes can also
identify sensitive material or reveal membership; a digest is not anonymization.
Prefer reviewed hashes/metadata when payload bytes are unnecessary. Any
malicious executable material kept elsewhere requires separate access controls,
bounds and isolation, and remains non-executed in this workflow.

Track permission to analyze, redistribute and train as separate decisions with
source license/terms and review references. Public availability and this
repository's MIT license do not grant rights over upstream samples, advisories,
model outputs or weights. Unresolved rights or privacy questions for the
intended use block that use pending appropriate review; neither the validator
nor an agent should invent a legal conclusion. Local evaluation needs analysis
and privacy approval; it does not require permission to train or redistribute.
Training additionally needs training rights; external sharing separately needs
redistribution and provider-sharing permission. A locally valid manifest grants
no permission to upload it.

The metadata contract separately records commercial-training rights and the
proprietary provider's permission for downstream training on its output or
derivatives. Generic analysis/training permission does not supply either grant;
unknown or denied rights block the corresponding declared use. Provider terms
need their own reviewed basis, including inherited restrictions from actual
ancestors. A human rewrite does not erase model/provider derivation. Provider
sharing, provider retention/reuse of user inputs, commercial service operation
and resale remain separate questions, not permissions inferred by these fields.
Historical public exposure must remain recorded even when redistribution is
now denied; exposure and future-use eligibility are different facts.

Proprietary frontier/API outputs and their derivatives are ineligible for
training, including distillation, unless the applicable provider terms or
license explicitly permit the intended use. Commercial training additionally
needs that scope covered by the reviewed terms. Do not infer that permission
from a paid account, API access, local inference or an output-ownership claim.

Generation evidence must bind the generator/run revision, model lineage where
applicable, configuration, prompt/template and input/output identities, terms
and review basis through governed references. Record unknowns rather than
inventing reproducibility. The manifest carries bounded references and declared
generation method, not raw prompts, answers, secret paths or payloads. Reviewed
provenance and known generation method are prerequisites for eligibility;
unresolved provider ancestry blocks training/redistribution without by itself
prohibiting separately permitted local evaluation. The validator does not
inspect the referenced evidence or prove the declarations true.

Synthetic, inferred and mutated records remain research evidence until a
separate review supports an appropriate production rule or intelligence change.
Never auto-promote a generator's claim, a hash string or model agreement into
the shipped intelligence assets. Real advisory changes still require the
existing primary-source verification and positive/negative regression process.

## Training, development and held-out separation

Maintain separate training, public-development/evaluation and private-held-out
manifests. Quarantine unreviewed or unresolved candidates. Reserve splits before
model selection or optimization, grouping campaigns, source packages, exact
duplicates, mutations, paraphrases and teacher/student derivatives together.
Track parent links transitively: a fresh ID or different byte hash does not make
a derived example independent. Related examples must not bridge training and
evaluation partitions, including through a quarantined intermediary.

Private holdouts must never enter training, fine-tuning, distillation, synthetic
generation contexts, prompt examples, retrieval stores, embeddings, tuning
feedback, public issues/PRs, CI logs or unapproved external evaluators. Keep their
inputs, labels, hashes and identifying metadata outside the worktree with
separate access controls. Ignore rules reduce accidents; they are not access
control, encryption, or proof that a file was never committed.

Training and adversarial-example-generating models and agents must have no
access to reserved holdouts through files, prompts, contexts, retrieval,
memory, caches or retained traces. A process that reviewed a reserved case
cannot use that context to generate training or public regression material.
Constructing a new evaluation candidate is distinct from using an existing
holdout as a generation seed: isolate construction, record its provenance and
evaluate defenders independently before claiming a held-out result. This is a
required boundary for future research environments, not storage isolation or
model orchestration implemented by this metadata tool.

Treat benchmark contamination as an evaluation failure, not a caveat attached
to a passing score. Check content and lineage across the complete relevant
training/evaluation inventory, including prior dataset versions and teacher
training data where knowable. Mark missing inventories or unknown exposure as
unknown; do not convert a locally passing split check into proof of global
decontamination. Pretraining exposure may be unknowable for a third-party
model. Public fixtures are exposed benchmarks, so report that limit explicitly.

Separate scorer-only labels from permitted model input. Blind detection must
not receive `expected.json`, descriptive fixture names/paths, target rule IDs,
advisory labels that reveal the answer, sibling examples or previous reviewers'
answers. Instruction Guard's current AI input deliberately includes deterministic
reasons, severities and behavior labels; evaluate that interface as assisted
explanation and contract compliance, not independent detection.

Evaluate attacker/generator and defender/critic roles independently. A model
must not be judged solely on its own generated examples. Another process,
prompt, seed, quantization or provider alias of the same base checkpoint is not
automatically an independent model. Record shared ancestry and evaluator access;
use independently sourced cases and reviewer evidence as well as generated
ones. Student evaluations need holdouts outside the teacher's generation and
training lineage. Repeated holdout feedback is itself exposure: restrict detail,
log accesses, retire compromised holdouts and replenish from independent
families. Keep the compromised run invalid in the historical record.

## Adversarial development cycle

Use the following cycle only on authorized inputs and trusted static test code:

1. Record an attack hypothesis and its prerequisites, evidence scope and source.
2. Construct an inert adversarial fixture with fake data, no live infrastructure
   and no sample execution. Preserve parents, generator settings and hashes.
3. Evaluate AuraScan with existing trusted tests, injected runners and temporary
   roots/state. Keep AI transports mocked in normal pytest and CI.
4. Review any apparent miss against the actual production call path, expected
   detection, enabled phases, parser bounds and observed coverage. Record a
   supported detector bypass, unsupported hypothesis, false positive or missing
   evidence without promoting it to exploitability or compromise.
5. Apply a narrow fix when supported; add positive and negative regressions,
   including benign adjacent behavior and secret-free evidence checks.
6. Obtain independent review of the finding, fixture, fix and interpretation.
7. Retain the permitted metadata, exact evaluation identities and reviewed
   outcome; update lineage/exposure records before future training or scoring.

If a private holdout revealed the issue, do not copy it into a public regression
or training example. A sanitized derivative can still leak the same family.
Once developers inspect it to author a fix, prompt change or regression, retire
its claim to independent future held-out evaluation, even before publication.
Keep the original and derivatives private and excluded from training. Preserve
the original run's exposure status and mark later uses as exposed development
evaluation. When disclosure is separately authorized, record that exposure too;
publishing a fix or rule explanation can reveal the family without its bytes.
Prefer a separately sourced public regression that does not reveal the reserved
case, and replenish holdouts from independent families.
Do not erase a prior miss or rewrite the original expected result merely to
improve a later score. Correct mistaken labels through a versioned adjudication
that preserves the original result and explains comparability changes.

Corpus lifecycle uses the existing metadata fields: quarantine with every use
disabled; independent review while still ineligible; deliberate partition
reservation and explicit eligibility for each permitted use; retirement or
revocation by disabling affected uses while retaining reservations and history.
Validation is not admission, and admission is not training, publication or
production-model approval. Exposed holdouts retain their exclusions even after
evaluation eligibility is disabled.

## Record versioning and migration

Every research record family must carry its own exact `family/MAJOR.MINOR`
schema identifier. The implemented item-manifest family is
`aurascan-security-data/1.0`. Names such as
`aurascan-security-evaluation-run` and `aurascan-security-model-record` are
reserved for future contracts; no version, parser or writer for them is
implemented here. The initial item schema is 1.0; preceding draft labels were
never committed or published and create no migration requirement. These names
do not change AuraScan's existing runtime schemas.

A major version changes required fields, field meaning, permission defaults,
eligibility/split rules or other incompatible validation requirements. A minor
version may only add compatible descriptive information without changing those
meanings or granting authority. Readers must explicitly implement and declare
each accepted exact version, including any compatible minor; never infer
support from a shared major, ignore unknown fields, silently downgrade, or try
another schema after rejection. This validator supports only 1.0 and performs
no negotiation. Conformance bug fixes still require regression evidence and an
identifiable validator revision; they must not silently redefine the contract.

Migrations need an explicit reviewed field mapping, original and resulting
manifest identities, and a retained migration basis. Preserve item IDs, hashes,
sources, lineage, partition reservations, prior outcomes and exposure history.
New or unresolved rights/provenance default to unknown and affected eligibility
to false; never convert absent information to permission. Retain permitted
original records and link corrections or withdrawals rather than rewriting
historical evaluation results. Revalidate the relevant cross-split inventory
after migration; a structurally valid migration cannot remove contamination.
The [lifecycle and future migration guidance](../security-data/README.md#lifecycle-and-migration)
retains these conservative defaults. No migration engine is implemented.

## Frozen evaluation-run contract for future tooling

No evaluation runner, model orchestration or results database is implemented by
this groundwork. A future runner must produce immutable, versioned metadata
records with at least the following groups before claiming comparable results.

| Group | Required identity/evidence |
| --- | --- |
| Run and task | Opaque run ID, UTC date, task/protocol version, defensive/adversarial/critic role, blind or assisted input mode, evaluator/reviewer identities and independence disclosures. |
| Dataset | Exact manifest bytes SHA-256 and schema version, split and lineage inventory revision, ordered item IDs/revisions and artifact hashes, scorer-only label revision, access/exposure history and contamination verdict (`clear-within-reviewed-inventory`, `contaminated`, `unknown`). |
| AuraScan | Repository commit, application version, scanner/report schema and rule versions, relevant package-input/repository/Instruction Guard evidence versions, phase/mode/policy configuration, fresh/cached/skipped status and acquisition coverage. |
| Harness | Trusted harness/generator commit, canonical input/configuration hashes and serialization version, validator/prompt/policy versions, resource limits, relevant dependency/environment identities and evaluator settings. |
| Model, when used | Opaque provider configuration ID with no endpoint credentials, exact model/checkpoint/weights or hosted revision where disclosed, base/fine-tune/teacher lineage, runtime version, quantization/precision, adapters, tokenizer/chat template, prompt/input hash, decoding settings and seed where supported. Record unavailable identities as unknown. |
| Per-item observation | Expected outcome reference separate from observed rules/labels/actions, valid/invalid structured response, bounded reviewed evidence IDs, missing evidence, refusal/abstention, coverage, timeout/error/not-run status and independent adjudication. |
| Aggregates | Metric definitions and denominators, class/behavior strata, uncertainty estimates where justified, false-positive/false-negative counts, coverage/abstention rates, elapsed time, resource use and available token/cost figures with unknown values disclosed. |
| Retention | Privacy/rights review, permitted audience, retention/revocation policy, immutable evidence references, superseded/retracted run links and reason. |

Hash exact retained bytes; when normalized representations are used, version
the normalization and preserve the original permitted-byte digest. Input hashes
must identify what the model actually received, not merely the original fixture.
Generated archives need generator revision/settings and generated-byte identity.
Random finding UUIDs, mutable filenames, cache keys alone, model aliases and
marketing names are insufficient run identities.

Never score incomplete, refused, invalid, timed-out, skipped or not-run cases as
benign true negatives. Report coverage and failure rates separately; specify how
each affects the preregistered metric. State denominators for every rate and
include small-sample limits and manual-review burden: an always-block system
does not become useful by avoiding false negatives alone. Assess refusal
separately from malformed output; neither implies the other. Treat model
confidence as uncalibrated until measured. Compare models on the same frozen
tasks, labels, inventory and budgets; changes to those conditions start a new comparison
series or require a clearly identified rerun of the old baseline. Do not
overwrite historical results. A provider changing a hosted model behind an
alias weakens reproducibility and must be disclosed.

Historical comparability does not override privacy or rights revocation. Remove
restricted bytes when required and retain only permitted retraction/tombstone
metadata, including any resulting inability to reproduce a run. Do not silently
rewrite scores or imply that deleting a record untrains an existing model.

## Evaluation dimensions and model admission

Use task-specific evaluations rather than a single "security score":

- Malicious-behavior detection and benign/malicious discrimination, including
  false positives and false negatives stratified by behavior and evidence level.
- Parser ambiguity, incomplete input and multi-stage reasoning, with unsupported
  syntax and missing artifacts represented as missing coverage.
- Provenance, privilege boundaries and software-supply-chain reasoning, keeping
  source integrity separate from trusted behavior and observed installation.
- Prompt/instruction-injection resistance, structured-output reliability and
  deterministic tool-policy compliance, using inert inputs and validators.
- Secure remediation quality: prerequisites, bounded proposed changes, rollback,
  evidence-supported recommendations and refusal of unsupported repairs.
- Calibration, uncertainty and ability to identify missing evidence without
  inventing it; distinguish justified abstention from task failure.
- Runtime, memory, latency and available usage/cost under fixed evaluation
  budgets, alongside all quality and policy metrics.

A new model, fine-tune, runtime, provider, quantization or abliterated variant is
not superior because it is larger, newer, higher precision, advertised as better
on a benchmark, or less likely to refuse. Evaluate refusal reduction/abliteration
separately from reasoning, calibration, false positives/negatives, structured
output and policy compliance. Compare each changed configuration against a
frozen baseline; a less-refusing research model gets no production authority.
Independently evaluated adversarial models may have different refusal profiles
from defensive production candidates while retaining isolation and scope limits.

Set acceptance thresholds from measured development baselines, realistic error
costs, benign-case diversity, manual-review burden and operational resource
budgets. Record why each role-specific threshold is justified; do not invent a
universal accuracy percentage or claim an unmeasured baseline. Freeze the
protocol, thresholds and scoring before final held-out evaluation. Changes
motivated by that evaluation require a new comparison protocol and independent
holdouts, not repeated tuning against the same answers. Report denominators,
class strata and justified uncertainty intervals alongside the thresholds.
Rights, privacy, contamination and deterministic policy are mandatory gates;
better aggregate detection or fewer refusals cannot compensate for failure.
No numeric acceptance thresholds or automatic model-admission system are
introduced by this groundwork.

Retain useful model disagreement as reviewed metadata: independent model/run
identities, common input identity, disputed behavior/evidence IDs, bounded
accepted conclusions and adjudicated/unresolved status. Freeze initial judgments
before models see peer answers; record subsequent unblinding and adjudication
separately. Do not start logging raw rejected responses, source snippets,
secrets or exception text to obtain
training data. If a rejected-output pattern is worth a regression, construct a
separately reviewed, defanged test example and record its synthetic origin.

## Future deployment choices and open decisions

These contracts can support future deterministic/community scanning, opt-in
local or bring-your-own-model analysis, specialized AuraScan models, explicitly
consented escalation to larger models, enterprise/private inference, and
separately authorized external frontier-security partnerships. These are
possible deployment arrangements, not products implemented or promised here.
Core detection and safety policy must not depend on billing, model branding or
a commercial entitlement. Do not use OpenAI's Daybreak Blue or Daybreak Red
names as AuraScan tier names, or assume permission to resell/proxy third-party
capabilities. Any future commercial use requires its own scope and terms review.

Deferred decisions include corpus stewardship and reviewer independence,
private storage/access controls and retention/revocation mechanics, upstream
license/model-output rights, exposure tracking across external pretraining,
near-duplicate/campaign grouping, metric thresholds and class balance, robust
model/run attestation, and authorized experiment isolation. Decide these before
admitting affected data or claiming valid comparative results, rather than
silently filling unknown metadata with permissive defaults.

Explicit developer collection now supports selected public recipes/metadata,
existing fixtures and advisory references. It keeps acquisition, quarantine
admission and explicit validation separate; even validated candidates remain
ineligible. The small private seed exercises these boundaries, not model quality.
The collector does not import operational user data. There is no
customer export, telemetry, training/distillation pipeline,
model weights, inference service, attack executor, SaaS infrastructure,
subscription/billing/licensing enforcement, paid tier or release publication.
