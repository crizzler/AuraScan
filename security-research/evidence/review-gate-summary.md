# Review gate summary — Daybreak initial round

VERDICT: APPROVE (final gate, 2026-11-09)

- Baseline: `02ac13d` (AuraScan 0.15.0, rule catalogue 1.15.0).
- Scope of this final gate: the two residual quantitative claims left open by
  the previous re-gate, and confirmation that nothing else changed. No finding,
  severity, measurement or recommendation was reopened, and no adversarial
  probe was re-run.
- Reviewer scope: read-only. This file and the private verdict are the only
  files the reviewer wrote. No production code, test, workflow, packaging file
  or other role's deliverable was edited.

This is a sanitized summary. Detailed findings, raw command output and the
adversarial evidence remain in the program's access-controlled private evidence
root.

## Verdict at a glance

Both residual claims are corrected, the correction is provably confined to those
two sentences, and no other content moved. The round is approved. The
assessment's `NOT READY` recommendation and all ten findings stand unchanged.

## Status of the three blockers from the previous round

1. **Private path — resolved.** The baseline results file records `<repo root>`
   instead of an absolute local path, its pinned hash in `evidence-index.md`
   matches the current bytes, and the private-path sweep over
   `security-research/` returns no match. Three convention references that had
   named the private evidence directory were replaced with
   `<private evidence root>`.
2. **Coverage ledger — resolved.** The two stray scratch artifacts are no longer
   at the repository root; the adversary report cites the ledger path that
   actually exists; the ledger records 15 checked, 2 checked at reduced depth,
   1 checked-partial and 3 scoped-only — 18 examined of 21 scoped — and the
   report and candidate JSON state the same figures. Every examined entry
   carries a pointable evidence reference; the three scoped-only files are not
   counted as examined. The ten findings are unchanged.
3. **Assessment claims — resolved.**
   - R8 is described as verified by source inspection with the caller-disclosure
     impact `NOT EXECUTED` in all four named documents and their adjacent
     restatements.
   - The attack-surface counts read 15 ranked surfaces with S6 described as
     unranked, matching the 15-row inventory table.
   - The corpus-coverage statements are non-quantified and no surface-to-case
     mapping was invented.
   - The two sentences that still carried the retracted count of surfaces and
     the superseded ranking denominator — in the use-case document rather than
     the three named assessment documents — are now corrected in the same
     non-quantified wording and the same rank wording used elsewhere.

## What the reviewer checked this round

| Check | Command | Result |
| --- | --- | --- |
| Residual-claim sweep | grep over `security-research/` for the retracted surface-count forms and the old ranking denominator | no match, exit `1` |
| Corpus-coverage wording | read of `daybreak/red-use-cases.md:85-89` | no numeric count; the missing surface-to-case mapping is named |
| S12 rank | read of the same document's rank sentence, plus a row count of `architecture/attack-surface-inventory.md:34-51` | rank 7 of 15 ranked surfaces; table has 15 ranked rows |
| Edit scope | reversal reconstruction of the two corrected sentences against the gate-time file hash | reconstructed bytes reproduce the gate-time hash exactly; only those two sentences differ |
| No other content changed | file mtimes under `security-research/` and `findings/`, and the private evidence tree | only the corrected document and its rework report; private findings untouched |
| Repository state | `git status --porcelain` | only the two pre-existing tracked documentation modifications; no production code or test modified |
| Focused tests | `PATH=/usr/bin:/bin .venv/bin/python -m pytest -q tests/security_research` | `11 passed`, exit `0` |

The previous round's independent checks still stand as recorded in those
verdicts: all pinned hashes reproduced, the full suite passed under the sanitized
PATH (`5714 passed, 3 skipped`), the architecture audit exited `0` with zero
violations, and the corpus metrics were computed from an executed run.

## Claim precision

The final gate found no remaining quantified claim of surfaces without a corpus
case, and no remaining superseded ranking denominator, anywhere in
`security-research/`. The two corrected sentences are:

- the detector-bypass research objective, which now describes evasive variants
  across surfaces without a corpus case and states that no surface-to-case
  mapping has been established;
- the AI evidence-laundering evidence anchor, which now places S12 at rank 7 of
  the 15 ranked attack surfaces.

The edit was confined to those two sentences: reversing them reproduces the
byte-identical pre-fix document that the gate had reviewed, which also means no
finding reference, status line, evidence anchor, `NOT EXECUTED` label or
use-case ranking could have changed.

## What was not executed (accepted for this round, unchanged)

- Exploitation of R3, R4, R5, R7, R9, R10 — requires root, a devtools base, a
  disposable VM or a report-replay path.
- R8 caller-disclosure impact — still `NOT EXECUTED`; no probe is claimed.
- Live AI/provider calls — none were made or permitted.
- Real package builds, `makepkg`, package installation, `sudo`, `arch-chroot`,
  recovery actions, USB writes and network scans — none appear in any command
  record for this round.
- Private-holdout or real-world prevalence measurement — the corpus is public
  and synthetic, and the documents say so.
- Desktop vitest suites — not executed by anyone in this program.
- Full repository suite — not re-run in the final gate; the change is
  documentation-only, the focused set above passed, and the previous full-suite
  result remains the latest full-suite evidence.

Charter phases 2, 4, 5, 6, 8 and 10 remain `NOT EXECUTED` and are named in
`README.md`, `testing/privilege-boundaries.md` and `evidence-index.md`. The
assessment's `NOT READY` recommendation is unchanged, as are all ten findings.

## Safety observations

- No production code changed in these reworks; the changes are documentation,
  claim wording, the evidence index and one recomputed hash.
- The fixtures remain inert: only `example.invalid` hosts, no live
  infrastructure, no payload that does anything.
- The two tracked documentation files modified before this program began
  (`AGENTS.md`, `docs/RELEASE_CHECKLIST.md`) are still pre-existing worktree
  changes, not this program's edits. The working-tree `AGENTS.md` continues to
  omit invariants present at HEAD, so the round read a reduced contract.

## The single change that would most improve the package

One machine-generated, hash-pinned evidence manifest — finding ID, claim class,
command, exit code, artifact hash — that the assessment documents cite by ID
instead of restating numbers by hand. Every claim-precision defect in this
program, including the two just corrected, comes from prose being the only copy
of an evidence class.
