# Security corpus metadata contract

This directory defines developer conventions for reviewed security data.
Collected candidates and source bytes stay in a private store outside the
worktree; see the [explicit intake workflow](../docs/SECURITY_DATA_INTAKE.md).
This directory contains no samples or production intelligence.
Existing regression fixtures remain under `tests/fixtures/`; their
current `expected.json` manifests and test harnesses remain unchanged.

Read [Security Model Research and Development](../docs/SECURITY_MODEL_RND.md)
for research, privacy, evidence, evaluation, and model-selection policy. This
document specifies the small offline metadata contract implemented by
[`tools/validate_security_data.py`](../tools/validate_security_data.py).
The validator is a standalone Python 3.8+ standard-library developer tool;
AuraScan's runtime does not import it or consume these manifests.

## Use and interpretation

Pass explicit manifest files together so overlap checks cover the intended
training, evaluation, reserved holdout, and relevant lineage records:

```text
python tools/validate_security_data.py MANIFEST.json ANOTHER_MANIFEST.json
```

`--help` prints usage. A leading `--` allows filenames beginning with a dash.
Relative and absolute manifest paths are accepted. Parent traversal, symlinked
path components, directories, special files, unstable or incomplete reads, and
oversized inputs are refused. There is no directory traversal or discovery.
Only the explicitly supplied manifest files are opened; artifact, source,
review, model, license, and evidence references are never followed or fetched.
The tool writes no files and makes no network, native-tool, or model calls.

Exit 0 prints aggregate manifest/item/eligibility/reservation counts and
`scope=provided-manifests-only`. Exit 1 prints the first fixed error code and
one-based manifest/item positions; position zero means no item was reached.
It does not print paths, record IDs, rejected values, underlying exceptions,
source text, or model prose. An empty `items` list is valid metadata structure,
not an evaluated dataset or evidence of coverage.

A passing result means the supplied metadata meets this version's structural,
permission-declaration, and overlap rules. It does **not** verify the referenced
bytes, licenses, reviewer independence, factual labels, redaction, privacy
clearance, model training history, or missing records. It grants no training,
publication, provider-sharing, network, execution, or release authority. Human
review and the referenced evidence remain necessary. Never silently export
runtime reports, histories, caches, user scans, or AI responses into this format.

## Version 1.0 document

The root JSON object has exactly two required fields:

| Field | Value |
| --- | --- |
| `schema_version` | Exactly `aurascan-security-data/1.0`. |
| `items` | Array of item objects described below. |

Every listed field is required. Unknown fields are rejected at every object
level. Use explicit empty lists, `null`, or the documented unknown/not-specified
status where evidence is unavailable; do not invent evidence to fill fields.
JSON duplicate keys, numeric tokens, NaN/Infinity, invalid UTF-8, surrogate
strings, and decoded control characters are rejected. This format has no numeric
fields: dates, versions, hashes, and opaque identifiers are strings; eligibility
values are actual JSON booleans.

Opaque identifiers use a type prefix followed by 12–64 lowercase hexadecimal
characters: `item-`, `family-`, `ref-`, or `model-`. These are references to
separately governed records, not paths or instructions. SHA-256 values are
exactly 64 lowercase hexadecimal characters. Revision references are exactly
40 or 64 lowercase hexadecimal characters. Neither formatting nor an asserted
hash authenticates the referenced object.

## Item fields

| Field | Required shape and meaning |
| --- | --- |
| `id` | Unique opaque `item-` ID in the supplied batch. Preserve this identity; do not relabel exposed material to reset its history. |
| `kinds` | 1–11 unique taxonomy tags from the list below; categories may overlap. |
| `origin` | `real`, `synthetic`, `mutated`, or `inferred`. A mutation requires at least one parent. |
| `provenance` | Object with `status` (`reviewed` or `unknown`), `basis_refs`, and `proprietary_provider_derived` (`yes`, `no`, or `unknown`). Reviewed provenance requires a basis reference. |
| `generation` | Object with `method`, `model_refs`, and `basis_refs`; see generation provenance below. |
| `collected_at` | Valid calendar date `YYYY-MM-DD`. Collection is separate from incident date and verification date in referenced evidence. |
| `sources` | 1–16 source objects described below. |
| `family_id` | Opaque `family-` identifier shared by related originals, mutations, generated variants, and derivatives. |
| `parent_ids` | 0–16 unique opaque `item-` IDs for direct derivation parents. Never omit a parent to obtain a different split. |
| `artifact` | Object with `kind` and `sha256`: `metadata_only` requires `null`; `digest_only` or `inert_fixture` requires a SHA-256. No payload or artifact path is stored. |
| `classification` | `benign`, `malicious`, `suspicious`, or `unknown`; an asserted label is distinct from validated behavior and observed detection. |
| `claim_level` | `none`, `suspicious_behavior`, `detector_bypass`, `exploitability`, or `compromise`. These name distinct evidence claims, not automatic promotions. |
| `behavior` | Object with `verified` and `suspected`, each 0–32 unique symbolic labels; the lists must be disjoint. Labels match `[a-z][a-z0-9_]{0,63}`. Store supporting detail in reviewed evidence, not sample prose. |
| `affected_versions` | 0–32 distinct literal AuraScan application-version strings, starting with a digit and containing at most 64 ASCII letters/digits or `. + ~ : -`. No range evaluation is performed. Empty means unspecified/not applicable. |
| `expected` | Result expectation object described below; keep it independent of observed detector/model output. |
| `observations` | 0–32 observed-result objects described below. An empty list means no retained result, not a passing evaluation. |
| `review` | Object with `status` and `basis_refs`; see validation rules below. |
| `rights` | Object with `analysis`, `redistribution`, `training`, `commercial_training`, `provider_training`, `basis_refs`, and `provider_basis_refs`; see purpose-specific permissions below. |
| `privacy` | Object with `status`: `clear`, `sensitive`, or `unknown`; and `visibility`: `public` or `private`. Visibility records exposure, not permission for a future use. Clear means reviewed clearance is asserted, not that a lexical filter proved absence of secrets. |
| `partition` | `quarantine`, `training`, `evaluation`, or `private_held_out`. This reservation persists independently of current eligibility. |
| `eligibility` | Object with boolean `training`, `commercial_training`, `evaluation`, and `redistribution`. Training and evaluation cannot both be true; commercial training also requires training eligibility. Partition assignment alone does not make an item eligible. |

Taxonomy tags are:

- `public_benign`: publicly sourced benign examples.
- `historical_malicious`: historical malicious examples; retain verification basis.
- `advisory_incident`: real advisory or incident material.
- `synthetic_adversarial`: synthetic adversarial examples.
- `detector_bypass`: detector-bypass attempts or demonstrated bypass records.
- `false_positive`: false-positive review examples.
- `remediation_fix`: remediation or fix examples.
- `model_disagreement`: disagreement evidence between independently identified models.
- `regression_fixture`: regression fixture metadata.
- `package_observation`: selected package metadata or recipe evidence without an inferred benign/malicious label.
- `private_held_out`: privately reserved evaluation items.

Tags do not themselves verify a claim, prove an item real, or authorize use.
For example, a bypass attempt is not automatically a demonstrated bypass; its
origin, claim level, observations, and review status must preserve that distinction.

## Sources, results, and validation

Each source has exactly `kind`, `reference`, `revision`, and `sha256`.
`kind` is `public`, `private`, or `generated`. Public references are bounded
ASCII HTTPS URLs with a DNS hostname, optional port 443, and no userinfo, query,
fragment, controls, or backslashes. Private/generated references are opaque
`ref-` IDs. `revision` and `sha256` are independently nullable; preserve both
when known. Source references are provenance, never fetch instructions or trust
signals. Use a governed reference for the actual source license, version,
attribution/redistribution conditions, collection authorization, and unresolved
rights questions; do not copy private paths or credentials into public URLs.

Generation method is `none`, `human`, `tool`, `model`, `mixed`, or `unknown`.
`none` is permitted only for real material with no claimed generation step.
`mixed` includes model generation combined with human or tool work.
Human/tool/model/mixed methods require at least one basis reference; model/mixed
also require at least one opaque `model-` reference. None/human/tool methods
cannot supply model references. Both reference lists are unique and bounded to
16 entries. Unknown method is representable but prevents eligibility.

Governed generation evidence must bind the actual generator/run revision,
model/checkpoint when applicable, configuration and prompt/template identities,
input/output hashes, relevant terms, and review limitations. Preserve the input
examples in `parent_ids`, including actual model-derived ancestors of a later
human edit. Do not embed prompts, source text, model prose or credentials here.
The validator checks declared structure and references, not their contents or
whether an asserted absence of provider ancestry is true.

An expected result has exactly `outcome`, `action`, and `rule_ids`. Its outcome
is `detected`, `not_detected`, `incomplete`, `not_run`, or `not_specified`.
An observed result has exactly those three fields plus nullable opaque
`model_ref` and `evidence_refs`; its outcome cannot be `not_specified`.

`action` is `allow`, `warn`, `manual_review`, `block`, or `not_specified`.
`not_run` requires `not_specified` action. `rule_ids` contains 0–64 distinct
symbolic IDs matching `[A-Za-z][A-Za-z0-9_.:-]{0,95}`; it must be empty for
`not_detected`, `not_run`, or `not_specified`. These are observed/expected rule
IDs, not a declaration that every absent rule ran. The tool checks syntax,
not membership in the current production catalog.

Observed `detected` requires a rule ID or model reference. Every observation
except `not_run` requires at least one evidence reference. Reference lists
contain at most 16 unique opaque `ref-` IDs. Keep incomplete and unrun outcomes
separate from negative results. An `allow` action is not a benign label or
proof of safety. Model refusal, correctness, calibration, and policy compliance
require separate future evaluation measures and cannot be inferred here.

Review status is `unreviewed`, `human_validated`, `deterministic_validated`,
`independently_validated`, or `rejected`. Every status except `unreviewed`
requires at least one `basis_refs` entry. Verified behavior and demonstrated
bypass/exploitability/compromise claims require a validated review status.
`deterministic_validated` alone cannot establish exploitability or compromise.
The reference must identify the actual claim, evidence, review method, reviewer
independence where relevant, and limitations. This tool does not verify those
assertions, perform experiments, or convert model agreement into ground truth.

## Eligibility and permissions

Rights for `analysis`, `redistribution`, `training`, and `commercial_training`
are independently `allowed`, `denied`, or `unknown`. Any allowed purpose requires
at least one opaque licensing/consent/policy `basis_refs` entry. Security review and rights
review are separate. Unknown rights require review for that purpose; never
infer permission from public availability, a repository license alone, or the
ability to download a model or sample.

`provider_training` records permission under proprietary provider/source terms
to use provider-derived material for downstream model training. Its statuses
are `allowed`, `denied`, `unknown`, and `not_applicable`. Allowed requires a
separate nonempty `provider_basis_refs` list; not-applicable is permitted only
when proprietary-provider ancestry is explicitly `no`. This field does not
authorize sharing inputs with a provider, provider retention or provider reuse
of user submissions. Those purposes need separate review. Each governed rights
basis must identify the particular purpose, material and applicable terms.

Every eligible use requires allowed analysis, clear privacy, validated security
review, reviewed provenance, a known generation method, and an artifact digest
or independently bound source revision/hash. Local evaluation may retain
unknown proprietary-provider ancestry and denied/unknown training or
redistribution rights; those uncertainties do not themselves prohibit allowed
local analysis. Training and redistribution require known provider ancestry.

Training additionally requires allowed training rights. Proprietary-provider
derivatives also require explicitly allowed provider-training rights with their
separate basis. Commercial-training eligibility requires training eligibility
and allowed commercial-training rights. Neither ordinary training eligibility
nor permission to download a model grants commercial use or service resale.
An explicit provider-training denial blocks training even if another provenance
field claims no proprietary derivation. Provider basis references must cover
the intended training purpose, including commercial scope when requested.
Redistribution eligibility independently requires allowed redistribution rights;
unknown or denied permission blocks that flag even when training is allowed.
The validator does not export, publish, train, or grant execution authority.

Rights, unresolved provenance and unknown generation in actual parents restrict
descendant uses transitively.
A human edit or a child's `proprietary_provider_derived=no` assertion cannot
erase an ancestor's unresolved provenance or restricted training terms. This
inheritance follows derivation parents; unrelated records sharing a conservative
family/source grouping do not automatically acquire one another's rights.

Historical public exposure remains representable alongside denied or unknown
redistribution rights. Do not change `visibility=public` to private to hide
exposure or make a validation pass. Visibility is not an export gate:
`eligibility.redistribution` is the separate declared-use check, and actual
publication still requires authority and review.

Training eligibility requires the `training` partition. Evaluation eligibility
requires `evaluation` or `private_held_out`. Quarantine is always ineligible.
Sensitive/unknown privacy and unreviewed/rejected validation prevent every use.
Metadata-only items may be eligible when their source identity is bound; no
payload bytes need be stored. Do not mark missing evidence as verified merely
to satisfy a schema. Avoid retaining secrets, identifying paths, or executable
malware material; hashes and bounded reviewed metadata are often sufficient.

## Split separation and scope

The batch validator rejects duplicate item IDs and builds connected components
from exact artifact hashes, family IDs, and parent/derivative links, including
transitive links through quarantined or currently ineligible items.
Metadata-only source hashes share the artifact-hash identity space. Such items
also join on equal source reference plus revision, independently of whether a
source hash is available. Public source identity comparison normalizes hostname
case, default HTTPS port, and an empty path. A revision alone never joins
different source references.

This source granularity is deliberately conservative: one advisory or broad
source reference can describe several examples. Shared source identity may
therefore reserve them together. Preserve a more specific reviewed source
identity when appropriate; do not erase real lineage to bypass a conflict.
The checker does not find near-duplicates, semantic equivalents, alternative
URL spellings, hidden derivations, or model pretraining overlap.

A connected component cannot span training and either evaluation partition,
even when some eligibility flags are false. Unknown parents are permitted only
for quarantined records; no eligible descendant/component may rely on that
unresolved lineage. Shared unknown parent IDs still connect records. Parent
cycles are invalid. Supply the relevant lineage manifests explicitly rather
than letting the validator discover private directories.

Private holdouts require private visibility and the `private_held_out` taxonomy
tag. The tag requires that same partition. A component containing a reserved
private holdout cannot contain any publicly visible item, including public
regression fixtures and their derivatives, or any redistribution-eligible item.
Public provenance references alone
do not mean the item record is public, nor prove a public source was unseen
during pretraining.

Retire or quarantine the **use** of an exposed/contaminated holdout by setting
evaluation eligibility false while retaining its private-held-out reservation
and lineage. Do not move it to training, delete its reservation, invent a new
family, or remove public exposure from the audit history. Record exposure and
invalidated evaluation runs in the separately governed evaluation history;
this version does not implement a historical exposure registry. A partial
manifest batch cannot certify global split separation. Benchmark contamination
is an evaluation failure, not evidence of model improvement.
Disabling eligibility does not make a publicly exposed reserved holdout valid:
retain the failing exposure record and reservation in governed history. Private
development exposure may instead leave a structurally valid, ineligible record.

## Lifecycle and migration

Use the existing fields rather than inventing a second lifecycle status:

1. Record a candidate in quarantine with every eligibility flag false.
2. Review provenance, generation, security claims, privacy and rights; validated
   review alone leaves the record ineligible.
3. Reserve the intended partition, check the relevant lineage inventory, and
   enable only the separately approved use flags.
4. On retirement, exposure or revocation, disable the affected flags and retain
   partition, lineage, rights decisions and historical evidence. Do not erase
   a holdout reservation or a prior public exposure to make another use pass.

The developer intake implements capture, candidate creation and explicit review
only. It always retains quarantine and false eligibility flags; later partition
admission, permission approval and export are outside that tool.

Version 1.0 is the initial schema. Earlier labels were uncommitted development
drafts, with no published contract, repository consumer or historical corpus
requiring migration. The validator accepts only the exact 1.0 identifier,
rejects unknown versions, and performs no migration or version negotiation.
The [research versioning policy](../docs/SECURITY_MODEL_RND.md#record-versioning-and-migration)
also governs future record families.

Any future migration requires explicit review of a new retained copy, not an
in-place rewrite. Preserve item IDs, collection dates, source/artifact hashes,
parents, families, partition reservations, observations and exposure history;
retain the original manifest digest and migration basis in governed history.
New or unresolved provenance and rights remain unknown, and affected eligibility
stays false until reviewed. Do not infer permission from an older eligibility
flag. Keep existing rights declarations as historical evidence, then
revalidate the complete relevant batch before enabling an approved use. A known
contamination conflict remains a failure after migration. No migration utility,
historical registry, training job or exporter is implemented.

## Bounds and adoption

One invocation accepts 1–32 explicit files, at most 1 MiB per file, 8 MiB total,
and 4,096 items across the batch. JSON nesting is limited to 48 and decoded
nodes to 65,536 per document; strings are at most 2,048 characters and individual
fields have the tighter bounds above. Manifest path input is at most 4,096 UTF-8
bytes and 64 components. Reads require regular files, no-follow descriptors,
stable file/path identity and metadata, and an exact captured byte count.
These bounds are risk reduction, not a sandbox or a guarantee about blocking
filesystem I/O.

For future adoption, reference an existing fixture and its exact repository
revision through reviewed source metadata rather than copying its payload into
this directory. Record generated-archive inputs, generator revision, limits,
and resulting artifact hashes in the evidence behind those references. Existing
public fixtures are regression/development material, not unseen benchmarks.
No license, provenance, ground-truth, or training permission is retroactively
assigned to them by this scaffold.

Keep private manifests and heldout evidence outside the public worktree. Review
any intentionally public metadata before committing it; filenames and opaque
IDs do not establish privacy. Offline regressions in
`tests/test_security_data_contract.py` exercise permission, provenance, lineage,
version and malformed-input boundaries with temporary inert metadata; the
existing CI full-pytest gate already includes them and needs no new workflow.
Detailed model, runtime, prompt, budget, dataset-manifest, and metric identities
belong in the future evaluation-run contract described in the design document; they are not
silently inferred from these item records.
