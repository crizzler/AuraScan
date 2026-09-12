# Runtime intelligence schema 1.0

This public runtime contract is independent of `security-data/1.0`, whose records
are research candidates and cannot be published automatically. Both the payload
and signed manifest require `schema_version: "1.0"` and the fixed
`feed_id: "aurascan-intelligence"`. Unknown fields, duplicate JSON keys,
non-finite numbers, unsupported capabilities, and incomplete records fail
validation. The application validator is normative.

The payload requires `reviewed_at` (ISO date), `npm_campaigns`,
`vendor_advisories`, and `withdrawals` arrays. Collections and strings are bounded;
the complete payload may not exceed 2 MiB. Every campaign, vendor advisory, and
withdrawal requires `rights: {redistribution: "permitted", basis: ...}`. The
basis must document the actual publication-rights review, not merely assert
that material was publicly downloadable. This is permission to distribute
these reviewed indicator facts; it grants neither training rights nor artifact
execution rights.

| Record | Required fields and meaning |
| --- | --- |
| npm campaign | `id`, `reviewed_at`, HTTPS `references`, `rights`, `packages`, `payload_sha256`, `malicious_domains`. Campaign identity scopes the claims; a future campaign never inherits another campaign's attribution. |
| npm package | `name`, exact `versions`, `advisory_ids`, HTTPS `references`, `broad_advisory` (`none` or `all_versions`). Exact observations do not establish maliciousness for unlisted versions. Broader coverage requires the corresponding authoritative advisory. |
| Vendor advisory | `id`, `cve`, Arch `package`, `fixed_floor`, `comparator` (`chromium_four_part`), `known_exploited: true`, HTTPS `vendor_reference` and `exploitation_reference`, `reviewed_at`, `rights`. Unsupported version semantics require an application update. |
| Withdrawal | `id`, `reason`, `reviewed_at`, HTTPS `references`, `rights`. The ID is the exact previous detection identity returned by the validator's `record_identities()`, not an instruction or a severity override. |

Vendor detection identities include the advisory ID, package, CVE, comparator
and fixed floor. Each altered claim therefore requires its own source-attributed
withdrawal. Retain prior withdrawal IDs. Removing a reintroduced indicator
requires renewing its reason, source references or later review date; an unchanged
earlier correction, a rights-only edit, cosmetic whitespace or reordered
references cannot authorize another removal. Earlier signed bundles and the
publisher repository retain the previous review records.

The manifest requires the fixed schema/feed, positive monotonic `sequence`,
`payload_sha256`, `payload_size`, exact supported `engine_capability: "1.0"`,
and UTC `issued_at`/`expires_at` timestamps (`YYYY-MM-DDTHH:MM:SSZ`). Maximum
validity is 30 days; future issuance beyond five minutes is refused. The
manifest and its detached signature are each limited to 64 KiB. Manifest
signatures bind the payload bytes through the digest and size. Neither manifest
nor payload may supply signing keys, URLs for key retrieval, alternate download
destinations, executable matchers, or settings.

This unpublished format begins at `1.0`. Any incompatible field, semantic,
comparator, or permission change requires a new schema/capability version and a
reviewed application migration. Clients reject unknown versions rather than
guessing. Migrations must preserve attribution, rights, withdrawals, and
rollback state; missing rights never become permission. Editorial documentation
changes alone do not change the wire format. No previous public schema exists
and no migration from a purported `2.0` is provided.
