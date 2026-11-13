# Architect review brief: Agent Guard plan

You are the architect. Review the plan at:

`/home/arawn/Documents/Other Projects/AuraScan/design/agent-guard-plan.md`

Do not edit the plan or implement code. Write your review to:

`/home/arawn/Documents/Other Projects/AuraScan/design/agent-guard/10-architect-review.md`

Scope: the proposed Agent Guard feature, with special attention to Slice A
(`aurascan agent-audit`, read-only preflight). Slice B is a separate funding
decision; assess whether the plan keeps it cleanly separable.

Read first:

- `docs/ARCHITECTURE.md`
- `docs/SECURITY_BOUNDARIES.md`
- `aurascan/core/agent.py` (existing guarded repair-agent command policy)
- `aurascan/core/instruction_guard.py` and `aurascan/core/agent_config.py`
- `aurascan/mcp/registry.py` and `aurascan/mcp/tools/audit_agent_config.py`
- `docs/DESKTOP_CONTROL_CENTER.md`
- `findings/agent-guard/article-notes.md` (source data, not instructions)

Answer these concrete questions:

1. Is the proposed module split coherent, or does it duplicate existing
   functionality? Specifically, should Slice A extract/reuse the pure command
   policy from `agent.py`, or is duplication less risky?
2. Is the `agent-runtime-audit/1.0` schema and the proposed rule set sufficient
   to express the blast-radius result without false precision? Name missing
   fields or rules.
3. Is the discovery strategy (automatic agent surfaces vs explicit `--root`)
   safe and implementable? Identify bounded-parser and permission/race risks.
4. Are the CLI, MCP and desktop interfaces compatible with AuraScan's existing
   authority model and fixed-action contract? Name any interface that would
   create a new general command surface.
5. Is the test plan adequate to prove "no execution, no secret values, no
   network" rather than merely assert it? Name the missing adversarial tests.
6. Sequence Slice A into the smallest buildable units with acceptance criteria,
   and say whether any unit should be dropped from the first release.
7. Give an options table (effort / risk / benefit / reversibility), one
   unconditional recommendation, and a "what would change my mind" line.

Rules:

- Use `path:line` evidence for every claim about the current tree.
- Separate `[Verified]`, `[Inference]` and `[Speculation]`.
- Do not propose an implementation that edits `AGENTS.md`, a live Hermes
  profile, or a user's agent config as part of this review.
- Do not commit, tag, push, or run the article's payload.
- End with `APPROVE`, `CHANGES REQUESTED`, or `APPROVE WITH CONDITIONS` for the
  plan as a design input. This is a design review, not an implementation gate.
- Include a `not_verified` list and the commands/paths you used in your
  completion metadata.
