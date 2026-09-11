# Explicit security-data intake

[`tools/collect_security_data.py`](../tools/collect_security_data.py) is a Python
3.8+ standard-library developer tool. Acquisition saves selected bytes and
metadata to a private store. A separate offline `intake` command creates
[`aurascan-security-data/1.0`](../security-data/README.md) candidates. A separate
`review` command records an explicit validation declaration. Every resulting
item stays in **quarantine with all eligibility flags false**, including after
review. There is no command for enabling a use or exporting a corpus.

The collector never invokes Git, a shell, package managers, PKGBUILDs, hooks,
payloads, fixture commands, models, or AuraScan's scan engine. It never discovers
operational reports, credentials, caches, user scans, or held-out data. No runtime
component imports the collector. The metadata validator remains read-only,
offline, and independent of acquisition.

## Sources and coverage

| Command | Explicit input and retained evidence | Limitations |
| --- | --- | --- |
| `fixture` | Selected existing fixture directory, public URI, asserted commit, `PKGBUILD`, `expected.json`, supported literal install hook; optional `--file` paths | Expectations are developer assertions, not benign/malicious truth. Other fixture files are not discovered. |
| `package` | Local exported Arch/AUR package base, canonical public URI, asserted full commit, optional parent commits; selected `PKGBUILD`, optional `.SRCINFO`, literal hook | No Git invocation or verification of the caller's revision assertion; no upstream source acquisition. |
| `arch-history`, `aur-history` | Explicit package base and 1–3 newest commit identifiers | Commit selection only; no corpus record or complete-history claim. |
| `arch`, `aur` | Explicit package base and full 40/64-hex commit IDs; upstream parent metadata and selected recipe files | HTTPS service assertions, not a cryptographically verified Git object graph. No archives, build sources, full trees, submodules, or ancestry expansion. |
| `aur-metadata` | Exact RPC package selection; name, package base, version, last-modified timestamp | Maintainers, emails, descriptions, votes, popularity, and other response fields are discarded. RPC and recipe evidence are distinct. |
| `advisory` | Manually supplied GHSA/CVE/ASA/AVG or supported incident identifier and primary-source HTTPS reference | Reference-only: neither the advisory body nor affected packages are fetched. No label, affected-version claim, or incident verification follows from recording a URL. |

Official recipe acquisition uses `gitlab.archlinux.org/archlinux/packaging/packages`.
AUR metadata uses its RPC interface; recipes/history use `aur.archlinux.org`
cgit. See the primary [Arch build-system documentation](https://wiki.archlinux.org/title/Arch_Build_System),
[AUR RPC documentation](https://wiki.archlinux.org/title/Aurweb_RPC_interface),
and [GitLab repository API](https://docs.gitlab.com/api/repositories/).
Package identity means package **base** for Git and AUR family grouping; an RPC
split package also retains its requested name and source URI in its receipt.
An absent `.SRCINFO` leaves the version unknown. The collector does not execute
a PKGBUILD to derive its version or licensing.

Remote commands refuse access unless that invocation supplies `--network`.
They use adapter-constructed HTTPS URLs, no proxies, redirects, credentials,
hooks, or challenge solvers. Host allowlists are fixed. HTML challenges and
unavailable/ambiguous commit or hook evidence fail the capture. There are no
automatic retries or mirror fallbacks. A network capture call is all-or-error;
already published capture objects from earlier commands remain available.

Source limits are 256 KiB per file/response, 1 MiB aggregate response bytes,
eight revisions and eight selected files, 40 requests, and a 45-second elapsed
transport budget. Reads and response parsing are bounded. Python's system DNS
resolver can outlast its socket timeout: use the external deadline shown below
when strict wall-clock enforcement is required. These controls reduce exposure;
they do not provide a sandbox or establish remote server integrity.

## Private store and identities

Initialize an explicit directory outside the worktree, under an existing safe
parent. It must be owned by the current UID with mode `0700`. Store objects and
the lock use `0600`; source blobs have no execute permission. All path components
are opened without following symlinks. The store checks ownership, modes, file
type, stable identity, size, and content hashes, with a nonblocking exclusive
lock. Ancestor/object replacement, links, malformed layout, or observed changes
fail closed. This is not protection against an already malicious same-UID
process or root.

The layout contains `blobs`, `captures`, `manifests`, and `reviews`; each object
is named by its exact byte SHA-256 (`.blob` or `.json`). JSON written by this tool
uses sorted keys, compact ASCII escaping, and one final newline. Publication
uses private temporary files, fsync, and no-replace links. Existing objects are
verified before reuse. A batch receipt is published last; no mutable current
pointer is maintained. Callers select an exact `--base` hash, so branches are
explicit and earlier snapshots remain intact.

Limits are 256 KiB per blob, 1 MiB per metadata object, 4,096 stored objects and
256 MiB total store bytes. Intake accepts at most 32 explicit capture IDs per
call, 256 candidate items, and 16 captures per item. A residual interrupted
temporary object blocks reopening rather than being pruned. Complete orphan
objects may be reused after integrity verification. Cleanup, retention,
revocation, encryption, backup policy, and multi-user authorization are not
implemented. Do not put notes or arbitrary files inside the store's layout.

Each captured file retains its SHA-256 and size. A content identity is the
SHA-256 of the canonical sorted array of `{path,sha256,size}` descriptors.
Thus the selected snapshot, including its file names and metadata, has a stable
identity independent of retrieval time. A candidate ID binds family, revision,
and that content identity. Retrieving identical content at the same revision
reuses the item and blobs while retaining distinct timed capture receipts.
Different revisions retain distinct item IDs even if their bytes match; this
preserves valid histories that revert earlier changes without creating parent
cycles. Content hashes and family IDs still connect them for split checks.

Family IDs bind source type and package base (AUR RPC and Git share the `aur`
namespace); advisory families bind their reference. Parent commit IDs are
preserved in capture receipts. `parent_ids` link only actually captured matching
revision items. Unselected ancestors are disclosed as partial history; family
grouping still reserves all observed package revisions together. A changed
snapshot or contradictory parent list at an already captured family/revision
is rejected. Exact snapshot content appearing under different families is
rejected for lineage review instead of being merged without explanation.

These checks cover the selected batch and its captured lineage. They do not
discover other stores, hidden ancestors, renamed packages, near-duplicates,
common files across otherwise different snapshots, or external pretraining.
Per-file hashes are retained for future reviewed overlap analysis. Use the
contract validator on the full intended split/lineage inventory before any
future admission. Public seed fixtures and packages cannot become private
holdouts merely by changing an ID or eligibility flag.

## Acquire, then admit

Commands below are templates: choose the store, selected fixture, public
reference, and complete commit IDs deliberately. The store's parent must exist.

```bash
python tools/collect_security_data.py --store /private/research/intake init
python tools/collect_security_data.py --store /private/research/intake fixture \
  --root tests/fixtures/curated_packages/simple_benign \
  --source-uri https://github.com/crizzler/AuraScan/tree/COMMIT/tests/fixtures/curated_packages/simple_benign \
  --revision COMMIT
timeout --signal=TERM --kill-after=5s 60s \
  python tools/collect_security_data.py --store /private/research/intake arch-history \
  --package pacman --limit 2 --network
timeout --signal=TERM --kill-after=5s 60s \
  python tools/collect_security_data.py --store /private/research/intake arch \
  --package pacman --revision SELECTED_COMMIT --network
python tools/collect_security_data.py --store /private/research/intake advisory \
  --identifier GHSA-q5c6-p5q5-g3px \
  --source-uri https://github.com/advisories/GHSA-q5c6-p5q5-g3px
python tools/collect_security_data.py --store /private/research/intake intake \
  --capture CAPTURE_SHA256 --capture ANOTHER_CAPTURE_SHA256
```

Acquisition prints capture hashes, not source bytes. Intake prints distinct
**batch** and **manifest** hashes. Subsequent commands take the batch hash;
the standalone validator takes the plain manifest file:

```bash
python tools/collect_security_data.py --store /private/research/intake inspect --base BATCH_SHA256
python tools/validate_security_data.py /private/research/intake/manifests/MANIFEST_SHA256.json
```

Every intake item has unknown classification, no behavior claim, unknown rights,
unreviewed provenance/privacy/generation, and all use flags false. Selected
public material records public exposure; that fact grants no permission. The
neutral `package_observation` taxonomy avoids inventing a benign label for
ordinary public recipes. Fixtures retain their explicit expected rule IDs and
action, separately from observations. Package license strings, registry
availability, signatures, or AuraScan results never enable use rights.

## Explicit review and separate assessments

Review the exact captured bytes as data and retain the validation basis outside
the worktree. Obtain the current item and manifest hashes with `inspect`, then
supply a UTF-8 JSON file with exactly these fields:

```json
{
  "schema_version": "aurascan-security-review-request/1.0",
  "item_id": "item-REPLACE_WITH_ITEM_HEX",
  "candidate_sha256": "REPLACE_WITH_CANDIDATE_SHA256",
  "manifest_sha256": "REPLACE_WITH_MANIFEST_SHA256",
  "reviewer_ref": "ref-REPLACE_WITH_REVIEWER_HEX",
  "status": "human_validated",
  "basis_refs": ["ref-REPLACE_WITH_BASIS_HEX"],
  "classification": "unknown",
  "claim_level": "none",
  "verified_behaviors": []
}
```

```bash
python tools/collect_security_data.py --store /private/research/intake review \
  --base BATCH_SHA256 --request /private/research/review-request.json
```

The placeholders intentionally are not valid records. Use actual SHA-256 values
and governed opaque references. A basis must identify what was validated, the
review method, actual reviewer/tool, evidence identity, and limitations. Allowed
statuses are `human_validated`, `deterministic_validated`,
`independently_validated`, and `rejected`; require a nonempty basis. An agent or
script must not claim that a human reviewed material. Deterministic checks alone
cannot establish exploitability or compromise. Missing/stale hashes and unsupported
fields fail; there are no review fields for changing rights, partition, or
eligibility. Validation status records a declaration, not authenticated reviewer
identity or independently proven label truth. An `unknown` label may remain
appropriate after validating a narrow metadata or static-behavior claim.

To retain an independently obtained AuraScan assessment, `assessment --base
BATCH_SHA256 --item ITEM_ID --request FILE` accepts exactly `schema_version`
(`aurascan-security-assessment-request/1.0`), `candidate_sha256`, `tool_revision`
(full commit), `scanner_version`, `scope` (`deterministic_control_text`), `outcome`,
`action`, and `rule_ids`. Outcomes/actions use the data contract's observed
result vocabulary. The caller must identify the exact trusted analyzer/input;
the collector does not run or attest it. Do not submit model prose, source
snippets, findings that depend on uncollected files, or whole-scan claims as a
control-text assessment. The resulting observation cannot alter the item's
label, verified behavior, validation status, rights, or eligibility.

Review/assessment receipts bind the exact earlier batch and candidate hashes;
loading a batch validates their shape and those bindings. New source or retained
parent metadata resets a candidate's review/claims to unreviewed/unknown in the
new batch, preserving the original decision in history. A repeated retrieval
with identical item metadata does not reset review. Historical detector
observations retain their exact earlier input statement.

## Versioning and what a collection proves

The initial unpublished corpus remains `aurascan-security-data/1.0`. Supporting
records independently require exact versions: `aurascan-security-capture/1.0`,
`aurascan-security-intake/1.0`, `aurascan-security-review-request/1.0`,
`aurascan-security-review/1.0`, `aurascan-security-assessment-request/1.0`, and
`aurascan-security-assessment/1.0`. Capture receipts contain source type/URI,
package/version/commit, parent revisions, UTC retrieval time, selected file
descriptors, coverage, raw transport response digests, and content identity.
Advisory time records reference intake, not retrieval of an advisory body.
Batch receipts bind a plain corpus manifest, per-item captures, evidence receipts,
parent batch, and creation time. Request and receipt schemas are distinct.
Unknown fields/versions, duplicate keys, excessive structure, nonfinite values,
and unsupported field types fail. Sidecars alone have bounded integer size
fields; the corpus manifest still contains no numeric fields.

The [incompatible-change and migration policy](SECURITY_MODEL_RND.md#record-versioning-and-migration)
applies to every record family: explicit retained-copy migration, preserved
identity/lineage/exposure, and no inferred permissions. Nothing migrates
automatically or negotiates an older permissive format.

Successful collection proves which bounded bytes and metadata this tool
retained, when, and under which asserted source identity. Structural validation
checks declarations and overlap within the supplied inventory. Neither proves
authorship, licensing, redaction, safety, malicious intent, actual execution,
exploitation, compromise, full repository coverage, or readiness for training
or evaluation. The private seed is a workflow exercise, not a representative
dataset, benchmark, new production intelligence, or empirical acceptance baseline.

Focused tests are `tests/test_security_data_{contract,sources,store,intake}.py`.
The existing full pytest CI gate includes them offline with injected transport
and temporary roots. It does not recollect the public seed or require services.
Training, synthetic generation, model admission, automatic labels, corpus
publication, and runtime changes remain outside this workflow.
