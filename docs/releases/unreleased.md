# AuraScan Unreleased

Changes after v0.9.1 will be recorded here.

## Agent Instruction Guard review explanations

- Terminal review now distinguishes integrity-only first-seen/change review
  from suspicious-content findings and prioritizes suspicious files.
- Content findings report deterministic one-based line ranges, semantic
  behavior labels, and fixed reasons without printing source snippets. An
  incomplete bounded scan is labeled as the current page with continuation
  still pending.
- Separately enabled AI receives only bounded opaque evidence IDs, fixed
  reasons, behavior labels, and deterministic locations. Its advisory
  rationales map to that evidence and cannot invent lines, establish trust, or
  claim execution or compromise. Clean first-seen files remain AI
  `not-needed`.
