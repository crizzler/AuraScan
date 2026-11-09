# Detector benchmark: versioned public corpus

Status: initial synthetic baseline. Baseline revision `02ac13d`, AuraScan
`0.15.0`, rule catalogue `1.15.0`, corpus version `1.0.0`.

## 1. Purpose and claim boundary

This benchmark measures whether AuraScan's existing deterministic analyzers
classify a fixed set of inert, structurally different fixtures as intended, and
whether they stay clean on matched benign controls. It is a regression harness,
not a measure of real-world detection quality.

**The first corpus is synthetic and public.** Every fixture, expected outcome,
and rule ID is committed to this repository and visible to any reader,
including model training pipelines. Therefore:

- It is **not a private holdout** and cannot support a private-holdout claim.
- It cannot support a **real-world prevalence** claim. Corpus proportions say
  nothing about how often any technique appears in real packages.
- It cannot support an **independence** claim. The fixtures and the detectors
  were written by the same project, so shared blind spots are expected.
- It cannot establish that AuraScan is safe, complete, or free of false
  negatives outside these nine cases.

A passing benchmark means: at this revision, these nine fixtures were
classified as declared. Nothing more.

## 2. Corpus format

The corpus is `security-research/testing/corpus/manifest.json` plus the
fixtures it names. Schema version `1`; corpus version `1.0.0`.

```json
{
  "schema_version": 1,
  "corpus_version": "1.0.0",
  "baseline": {"revision": "02ac13d", "aurascan_version": "0.15.0", "rule_version": "1.15.0"},
  "visibility": {"class": "public-synthetic", "exposed": true, "private_holdout": false},
  "families": [{"id": "encoded-command", "surface": "PKGBUILD control text", "description": "..."}],
  "cases": [
    {
      "id": "DB-ENC-001",
      "family": "encoded-command",
      "category": "obfuscated-execution",
      "role": "malicious-intent",
      "intent": "Decode inert text from base64 and pipe it to a shell.",
      "scanner": "deterministic_pkgbuild",
      "files": [{"path": "fixtures/pkgbuild-base64-exec/PKGBUILD", "sha256": "..."}],
      "expected": {
        "outcome": "FINDING",
        "rule_ids": ["EXEC-B64-001"],
        "absent_rule_ids": [],
        "min_severity": "CRITICAL",
        "blocking": true,
        "manual_review": false,
        "phases": ["pkgbuild_static"]
      },
      "reproduction": ".venv/bin/python -m pytest -q tests/security_research/test_detector_corpus.py -k DB-ENC-001"
    }
  ]
}
```

Required case fields:

| Field | Meaning |
|---|---|
| `id` | Unique, stable case identifier. Never reused for a different fixture. |
| `family` | One of the declared families. |
| `category` | Threat or benign category used for per-category false-positive rates. |
| `role` | `malicious-intent`, `benign-control`, or `coverage`. The label describes test semantics, not real-world use. |
| `intent` | One sentence describing the behaviour under test. |
| `scanner` | Which existing analyzer entry point scans the fixture. |
| `files` | Fixture-relative paths with pinned SHA-256 digests. |
| `entry_files` | npm only: local files already captured for lifecycle inspection. |
| `expected.outcome` | `FINDING`, `NO_FINDING`, or `INCOMPLETE`. |
| `expected.rule_ids` | Exact rule-ID set that must fire. Validated against `aurascan/core/rule_metadata.py`. |
| `expected.absent_rule_ids` | Rule IDs that must not fire; the benign-control precision check. |
| `expected.min_severity` | Severity floor, or `null` when no finding is expected. |
| `expected.blocking` / `manual_review` | Required policy behaviour. |
| `expected.phases` | Exact evidence phases that may appear. |
| `reproduction` | Focused command for the case. |

The test copies every fixture directory into `tmp_path`, recomputes each
SHA-256, and scans the copy. A changed fixture byte fails until the manifest and
its expected outcome are reviewed together.

### Scanners

| `scanner` value | Existing entry point | What it inspects |
|---|---|---|
| `deterministic_pkgbuild` | `DeterministicAnalyzer.analyze_pkgbuild` | PKGBUILD control text. |
| `source_metadata` | `SourceMetadataAnalyzer.analyze_pkgbuild` | Declared `source`/checksum metadata. |
| `install_hook` | `capture_package_scan_input` + `DeterministicAnalyzer.analyze_install_script` | The declared install hook, captured through the bounded no-follow resolver. |
| `npm_install_audit` | `audit_npm_install` | A `package.json` and the local lifecycle entry text already captured. |

Metrics are **analyzer-level**. They do not include the engine's risk summary,
policy action, cache behaviour, JSON report, wrapper decision, or AI layer.

## 3. Metric definitions

Let a case **pass** only when all of the following match the manifest: exact
rule-ID set, absent-rule set, severity floor, blocking flag, manual-review flag,
and evidence phases. A superset of expected rules is a failure, not a success.

| Metric | Definition |
|---|---|
| Detection rate | `malicious-intent cases that pass / all malicious-intent cases`. |
| False-negative rate | `malicious-intent cases that fail / all malicious-intent cases`. With this corpus every malicious case declares a finding, so this is the complement of detection rate. It does not count malicious behaviours that no fixture represents. |
| False-positive rate by category | Per family: `benign-control cases that emit at least one finding / all benign-control cases in that family`. |
| Regression rate across releases | `cases whose pass/fail classification changed between the previous recorded corpus run and the candidate run / cases compared`. A case that changes from pass to fail is a regression; a case that changes from fail to pass is a correction and is reported separately. First run: not measured. |
| Coverage of newly introduced surfaces | Two parts: (a) new families/cases added since the previous `corpus_version`, each with a malicious case and a benign control; (b) whether a newly introduced product surface has any corpus case at all. First run: only the baseline inventory is measurable. |

With one benign control per family, a per-category false-positive rate can only
be `0/1` or `1/1`. It is a tripwire, not a statistically meaningful rate. Do not
report confidence intervals or significance from this corpus.

## 4. Baseline results (executed)

Command:

```bash
.venv/bin/python tests/security_research/test_detector_corpus.py
```

Actual output, exit code `0`:

| Case | Family | Role | Expected | Actual rule(s) | Severity | Blocking | Manual review |
|---|---|---|---|---|---|---|---|
| DB-ENC-001 | encoded-command | malicious-intent | FINDING | `EXEC-B64-001` | CRITICAL | true | false |
| DB-ENC-002 | encoded-command | benign-control | NO_FINDING | none | — | false | false |
| DB-HOOK-001 | install-hook | malicious-intent | FINDING | `EXEC-INSTALL-HOOK-SUDO-001` | CRITICAL | true | false |
| DB-HOOK-002 | install-hook | benign-control | NO_FINDING | none | — | false | false |
| DB-NPM-001 | npm-lifecycle | malicious-intent | FINDING | `SUPPLYCHAIN-NPM-INSTALL-ENV-EXFIL-EVAL-001` | CRITICAL | true | false |
| DB-NPM-002 | npm-lifecycle | benign-control | NO_FINDING | none | — | false | false |
| DB-NPM-003 | npm-lifecycle | coverage | INCOMPLETE | `NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001` | HIGH | false | true |
| DB-SRC-001 | source-provenance | malicious-intent | FINDING | `SOURCE-META-GIT-SELECTOR-UNRESOLVED` | HIGH | false | true |
| DB-SRC-002 | source-provenance | benign-control | NO_FINDING | none | — | false | false |

Computed metrics from that run:

| Metric | Result | Denominator | Note |
|---|---|---|---|
| Detection rate | `4/4` | 4 malicious-intent cases | All expected rule sets matched exactly. |
| False-negative rate | `0/4` | 4 malicious-intent cases | No fixture missed its declared classification. This is not a general FN claim. |
| False-positive rate — encoded-command | `0/1` | 1 benign control | Tripwire only. |
| False-positive rate — install-hook | `0/1` | 1 benign control | Tripwire only. |
| False-positive rate — npm-lifecycle | `0/1` | 1 benign control | Tripwire only. |
| False-positive rate — source-provenance | `0/1` | 1 benign control | Tripwire only. |
| Regression rate across releases | `not measured` | 0 prior runs | Corpus `1.0.0` has no predecessor to compare against. |
| Coverage of newly introduced surfaces | `not measured` | — | First corpus release: 4 families, 9 cases. No product-version-to-corpus mapping exists yet. |

Additional executed check: `NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001` is
asserted as non-blocking but `requires_manual_review=True`, so the incomplete
case cannot be mistaken for a clean scan.

## 5. Regression procedure

1. Record the baseline as done here: corpus version, git revision, AuraScan
   version, rule version, per-case rule IDs, flags, and the pytest result.
2. On a candidate revision, run the same command against the same corpus
   version.
3. Compute the regression rate over the cases present in both runs. Report
   pass→fail and fail→pass separately; do not net them.
4. If a case's expected outcome changes deliberately, bump `corpus_version`,
   document the reason, and treat the new corpus as a new baseline. Never edit
   an expectation only to make a run green.
5. Add a new case, not a looser assertion, when a new representation is needed.

A release-to-release regression rate is only meaningful once at least two
recorded runs exist. Until then it must be reported as `not measured`.

## 6. Coverage of newly introduced surfaces

To measure this, a release must map each new detector or trust surface to at
least one malicious case and one benign control, then compare against the
previous corpus version. The initial round does not have a prior version, so
the only honest statement is the baseline inventory:

| Family | Surface | Malicious | Benign | Coverage case |
|---|---|---|---|---|
| encoded-command | PKGBUILD control text | DB-ENC-001 | DB-ENC-002 | — |
| install-hook | declared install hook | DB-HOOK-001 | DB-HOOK-002 | — |
| npm-lifecycle | npm manifest + local lifecycle entry | DB-NPM-001 | DB-NPM-002 | DB-NPM-003 |
| source-provenance | declared source metadata | DB-SRC-001 | DB-SRC-002 | — |

Surfaces with **no** corpus case in this round include: deep-static acquired
source, nested archives, repository-provenance artifacts, Python bytecode
carriers, editor tasks, Cursor/MCP configuration, AI provider boundaries,
recovery artifact verification, and updater signatures. Their absence is a
coverage gap, not a clean result.

## 7. Reproduction

```bash
# All corpus cases and the manifest-integrity checks.
.venv/bin/python -m pytest -q tests/security_research/test_detector_corpus.py

# Per-case table and computed metrics.
.venv/bin/python tests/security_research/test_detector_corpus.py

# Required focused gate (corpus + wrapper + MCP guards).
.venv/bin/python -m pytest -q tests/security_research tests/test_makepkg_wrapper.py tests/test_mcp_path_guards.py

# Corpus integrity.
cd security-research/testing/corpus
sha256sum manifest.json
find fixtures -type f -print0 | sort -z | xargs -0 sha256sum
```

Actual results and exit codes are recorded in
`security-research/evidence/test-results/2026-11-09-baseline.md` and the hashes
in `security-research/evidence/evidence-index.md`.

## 8. Known limitations

- **Synthetic and exposed.** The corpus is public and cannot be a holdout.
- **Small.** Nine cases, four families, one benign control per family.
- **Analyzer-level.** No engine policy, wrapper handoff, cache, report, or AI
  behaviour is measured.
- **Representation-bounded.** Each family exercises one or two representations;
  the charter's full variant list (formatting, variable expansion, encoding,
  indirection, dependency relations) is not covered.
- **Author overlap.** Fixture and detector authors are the same project.
- **No hostile execution.** The corpus intentionally never runs a fixture, so
  it cannot measure dynamic behaviour, sandbox escape, or runtime containment.
- **No prevalence inference.** Do not use these proportions as an estimate of
  real package maliciousness or detector field accuracy.
