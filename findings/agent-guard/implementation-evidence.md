# Agent Guard implementation evidence

Date: 2026-11-14
Scope: A0-core plus the reviewed MCP and desktop projections. Slice B remains deferred.

## Delivered

- `aurascan/core/agent_runtime_audit.py`: fixed surface allowlists, no-follow
  identity-bound capture, bounded JSONC/JSON and TOML-subset parsers, execution
  channels, project secret-class inventory, coverage-first report, evidence
  digest.
- `aurascan/core/agent_audit_cli.py`: `aurascan agent-audit --root PATH
  --surface codex|claude|cursor|mcp [--json] [--explain]`.
- `aurascan/cli.py`: early dispatch and help entry. The audit runs before AI
  environment loading.
- `aurascan/core/rule_metadata.py`: four `agent_runtime` rules.
- `aurascan/core/presenter.py`: fixed user-facing templates for those rules.
- `aurascan/mcp/tools/audit_agent_runtime.py`: aggregate-only MCP projection over the server root.
- `desktop/src/views/AgentGuard.tsx`, desktop contract/parser and Electron bridge:
  native-directory, read-only Agent runtime view with no hardening action.
- `docs/AGENT_GUARD.md`, `docs/REFERENCE.md`, `docs/SECURITY_BOUNDARIES.md`,
  `README.md`, `docs/ARCHITECTURE.md`: command, scope, exit contract, boundary
  and module-inventory updates.
- `tests/test_agent_runtime_audit.py`: 25 passing tests plus one optional
  `strace` test skipped when `strace` is unavailable.

## Contract implemented

- Exit `0`: every selected surface parsed and no execution authority was
  observed.
- Exit `1`: execution authority observed with complete coverage.
- Exit `3`: missing, unreadable, unsupported, malformed, symlinked, FIFO-like or
  ambiguous coverage; precedence over `0` and `1`.
- Exit `2`: usage; exit `4`: internal schema failure.
- Codex, Claude Code and Cursor include built-in shell authority. Hooks and MCP
  stdio commands add explicit channels.
- `AGENT-CREDENTIAL-EXFIL-RISK-001` is `cannot-rule-out` when execution and a
  project secret class coincide because A0 has no OS-level isolation proof.
- Secret values and secret paths are not emitted; home, environment, keyring and
  socket credentials are stated as out of scope.
- No model endpoint, model file, MCP server, hook, agent or project code is
  contacted or run.

## Verification

- New suite: `25 passed, 1 skipped` on Python 3.14.8; MCP focused suite `101 passed`;
  desktop suite `82 passed` with TypeScript and Vite build passing.
- New suite on Python 3.8.20: `25 passed, 1 skipped`.
- Full suite with `ANTICOPY_ROOT=/tmp/anticopy-golden-1860024`:
  `6101 passed, 5 skipped` in 348.60s.
- `python -m compileall -q aurascan tests`: exit 0.
- `tools/audit_presenter_coverage.py --strict`: exit 0.
- `tools/audit_presenter_coverage.py --strict-medium`: exit 0.
- `git diff --check`: exit 0.
- `ruff check` on the two new modules and the new test file: all checks passed.

An unpinned full-suite run later failed only the external AntiCopy parity test
because the live AntiCopy checkout advanced from the golden `1860024` pin to
`3736ab2`. The pinned worktree run above is the repository verification used for
this implementation.

## Not delivered

- Automatic discovery, home/global config merging, model identity or trust
  store, and the hardened launcher (Slice B). The MCP tool and desktop view are
  now delivered as aggregate, read-only projections.
  These are explicitly deferred by the reviewed plan. No claim of model safety
  or containment is made.

## Working tree state

No commit, tag, package release, or public artifact was created in this step.
