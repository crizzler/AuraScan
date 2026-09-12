# AuraScan intelligence publisher template

This directory prepares a future, separately maintained `aurascan-intelligence`
repository. It is developer tooling and is excluded from the installed AuraScan
runtime. It does not create a repository, signing key, release, or network
service. There is no configured production feed or trusted production key yet.

Use a pinned compatible AuraScan checkout or isolated developer installation.
`bundle.py` deliberately imports the exact runtime contract instead of keeping a
second, potentially divergent validator. The first supported schema and engine
capability are both `1.0`. Publish the pinned validating revision in the eventual
repository's contributor documentation. Updating that pin is a reviewed change.

## Admission and corrections

Only human-reviewed, source-attributed runtime intelligence enters a bundle:
exact npm package/version observations, explicitly established broader package
advisories, captured payload SHA-256 indicators, malicious domains, and vendor
advisories understood by application-owned comparators. The current comparator
is `chromium_four_part`. Supported records cannot select rules, severity,
commands, parsers, regular expressions, or policies.

Follow [the runtime contract](SCHEMA.md). A redistribution decision must be
`permitted` and have a specific review basis. Missing/unknown rights are rejected.
References and a filled rights field do not prove factual accuracy or establish
legal permission: maintainers must inspect the underlying evidence. Do not copy
private reports, held-out evaluation material, provider output, credentials,
malware payloads, or unreviewed research candidates into this repository. Research
intake and runtime publication are separate decisions.

Every build requires the preceding published payload as `--previous`; use the
bundled runtime baseline for the first release. Do not use an empty baseline to
bypass correction review. Removing an indicator, dropping a broader advisory,
or changing a vendor advisory's affected identity/floor requires a `withdrawals`
entry for its exact `record_identities()` identity, with review date, source
references, rights, and reason. `bundle.py identities preceding-intelligence.json`
lists those stable IDs for review. Carry every prior correction ID forward.
Vendor identities bind the exact package, CVE, comparator and version floor as
well as the advisory ID, so correcting a later floor requires a separate review
of that claim. If a withdrawn indicator is reintroduced and later withdrawn
again, renew its correction's reason, source references or later review date explicitly;
an unchanged old review cannot authorize another removal. Rights-only edits,
whitespace changes and reference reordering do not count as renewed review.
Retain earlier review records in the publisher repository and immutable bundles.
New clients must be able to validate the bundle against their bundled baseline,
and existing clients against their active generation. Corrections change only
the relevant intelligence and cannot waive application-owned behavior blockers.

## Offline preparation

Use the project's isolated developer interpreter. The following commands read
only explicitly selected JSON. They never download, execute, or install data:

```bash
python tools/intelligence_repository/bundle.py validate reviewed.json --previous preceding-intelligence.json
python tools/intelligence_repository/bundle.py build reviewed.json --previous preceding-intelligence.json --sequence 1 --issued-at 2026-09-12T00:00:00Z --output unsigned-bundle
```

Choose a new sequence above every previously published sequence, and the actual
UTC publication time. The example timestamp is illustrative. The output
directory must not already exist. Fixed inputs yield byte-identical
`intelligence.json` and `manifest.json`; the default validity is 30 days, never
longer. Review changes, run the template tests and complete AuraScan regressions,
then review the exact prepared bytes before signing.

## Signing and eventual publication

Production key provisioning and repository creation require a separate release
task. Keep the private signing key outside this repository, the downloader host,
and GitHub Actions; use a dedicated offline signing environment. Add only the
reviewed public key and exact full fingerprint to a future AuraScan application
release. The template never creates keys or invokes signing automatically.

In that separately provisioned signing environment, create an ASCII-armored
detached OpenPGP signature over the exact `manifest.json` bytes, named
`manifest.json.asc`, selecting the provisioned full fingerprint explicitly.
Export no private key and include no key URL or embedded key in the bundle.
Validate the result with the application verifier and a temporary injected test
store before publication. A signing key is authority to supply intelligence,
not proof that an indicator is correct. Initial key rotation and compromise
recovery require an application update; this is not a TUF implementation.

Enable GitHub immutable releases before the first public release. Upload exactly
the manifest, detached signature, and payload as one reviewed release. GitHub is
the transport; signatures and locally retained sequence state establish accepted
update identity. Do not replace an earlier sequence, even to fix a mistake.
Publish a newer signed correction. Configure the fixed production GitHub
repository and keys only in a separately reviewed application release.

The downloader follows only bounded HTTPS release redirects for the configured
repository to GitHub release assets. It has no proxies, authentication, scan
uploads, or API polling. The ordinary scanner remains local. An expired feed
retains previously verified detections and reports staleness; maintainers need
to publish a reviewed fresh manifest before expiry even when indicators have
not changed. This entails ongoing curation and signing work, with GitHub
availability and current service terms as external dependencies.

If first activation is interrupted before its pointer commits, leftover
generation data is ambiguous and automatic sequence-history reset is refused.
An operator must restore verified activation metadata and sequence history from
trustworthy evidence. Deleting the state directory to bypass this protection is
not a supported recovery workflow.

## Tests

```bash
python -m pytest -q tools/intelligence_repository/tests tests/test_intelligence_delivery.py
```

The tests generate small inert data under temporary roots. They do not supply a
corpus, exercise malware, sign with production keys, or contact GitHub. Complete
application validation additionally covers real temporary-key verification,
store transactions, cache invalidation, and scanner parity.
