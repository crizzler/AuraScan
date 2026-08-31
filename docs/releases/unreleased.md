# AuraScan Unreleased

Changes after v0.10.0 will be recorded here.

- Redesigned Agent Instruction Guard terminal reviews to distinguish
  suspicious instructions, new or changed files awaiting integrity approval,
  and incomplete inspection or discovery coverage. A clean first-seen file is
  now described as lacking a machine-bound approval, not as a malware finding.
- Made suspicious findings more actionable with exact one-based contributing
  line ranges, the semantic role of each range, and a fixed deterministic
  explanation of why the correlated behavior matters. Evidence-mapped AI
  reasoning remains separately labeled as advisory, reports its bounded
  explanation count, and cannot alter the deterministic location or severity.
- Classified malformed configuration as incomplete scan coverage instead of a
  suspicious instruction, and added a concrete approval or manual-review next
  step for changed files without duplicating their integrity finding.
- Improved terminal grouping and wrapping while keeping reports secret-free:
  source lines, snippets, credentials, and raw model prose are neither shown
  nor added to the existing Instruction Guard report contract.
