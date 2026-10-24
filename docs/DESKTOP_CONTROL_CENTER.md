# Desktop control center

The Electron shell under `desktop/` is currently a **read-only evidence
console**: it renders `aurascan ui --json` and cannot change anything. This
document is the plan and the authority contract for turning it into a control
center that configures and operates AuraScan.

It is not a promise that the shell becomes a general system console. Every
control in the app is a named AuraScan operation with a fixed argument list.
There is no shell, no terminal emulator, no arbitrary command, and no root
process in the app.

## Why this is not only UI work

A capability review of the CLI found that reading evidence is already headless,
but several mutations are not yet bindable to what a user saw:

| Operation | Headless today | Mutates | Needs root | Blocker for a safe UI |
| --- | --- | --- | --- | --- |
| Evidence snapshot (`ui --json`) | yes | no | no | none |
| Doctor checks (`doctor --json`) | yes | no | no | none |
| Security audit (`security-audit --json`) | yes | cache only | no | none |
| Settings (non-secret) | **added in this change** (`settings --json`) | no | no | none |
| AI credential | **added in this change** (`settings set-ai-key`, stdin) | user config | no | none |
| Instruction Guard review (`instruction-audit --review --json`) | yes | private state | no | none |
| Instruction Guard approve/disable | yes | file rename, state | no | `--approve` accepts no expected hash; triage-only binding |
| Incident diagnosis (`incidents --json`) | yes | private report | no | none |
| Incident repair apply | yes (`--dry-run` + `--yes`) | packages/services | **yes** | elevation; plan IDs already exist |
| Upgrade preflight (`upgrade --json`) | yes | no without `--yes` | no | none |
| Upgrade apply (`upgrade --yes`) | yes | packages/services | **yes** | elevation; no plan hash is returned |
| Config drift apply (`config-drift --yes`) | yes | files (+ backups) | sometimes | `action_id` is not in the JSON projection |
| Maintenance run | partly (`incidents --run-maintenance`) | services | **yes** | no JSON output, elevation |
| Recovery install/remove | yes | boot entry | **yes** | elevation |
| Hook install | only inside `init` | hook file | **yes** | no non-interactive path |

Two conclusions follow:

1. **Unprivileged control is available now** and covers settings, credentials,
   Instruction Guard review and triage, incident diagnosis, and every read-only
   view.
2. **Privileged control needs a decision** (below) before any button exists for
   upgrade, maintenance, recovery, or hook installation.

## Authority model

These rules apply to every phase and are not negotiable per feature.

- **The renderer never describes a command.** It sends an action ID plus
  declared parameters. `desktop/electron/main.cjs` owns the argv.
- **Main validates independently.** It re-checks the action ID and parameter
  types against its own copy of the catalog, and refuses anything not in it.
- **No shell, no interpolation.** `spawn` with an argument array, `shell: false`,
  fixed absolute `/usr/bin/aurascan`, allowlisted environment, no AI keys in the
  child environment.
- **Fresh consent per exact action.** A confirmation covers one action, one
  parameter set, and one evidence hash. Nothing is remembered, batched, or
  auto-approved. Repeating the action asks again.
- **Bind to what was displayed.** Where the CLI can produce a plan identity
  (`incidents` action IDs, Instruction Guard report SHA-256), the apply step
  must echo it back and the CLI must refuse a mismatch.
- **Secrets travel on stdin only**, never in argv, environment, logs, or the
  renderer. The app shows *presence*, never values.
- **The app never runs as root.** Privileged work is either handed to the
  terminal with the exact command shown, or performed by a fixed, unprivileged
  client under polkit — the pattern the detection-data tray already uses.
- **A mutation that the CLI refuses** is reported as a refusal, not retried with
  weaker flags. The app never adds `--yes`, `--no-ai`, or `--offline` on its own.
- **AI stays advisory.** The app can enable it, store a credential, and show
  results; it can never use AI to approve a file, lower a finding, or apply a
  plan.

## Phases

### Phase 1 — Settings and credentials (this change)

- `aurascan settings --json`: effective settings, provider inventory,
  redacted-with-presence AI state, feature switches, config file health.
- `aurascan settings set-ai-key --provider ID`: credential from stdin, written
  atomically to `~/.config/aurascan/.env` at mode `0600`, never echoed.
  Storing a credential does **not** enable AI; an explicit `AURASCAN_AI_ENABLED=0`
  is written when the flag was unset.
- Settings view in the renderer, reading this contract through a new fixed
  Electron operation.

### Phase 2 — Instruction Guard triage

- `instruction-audit --review --json` view with deterministic line ranges and
  reasons.
- Approve/disable/restore actions with report + SHA-256 binding. **CLI support is
  implemented**: `--approve` and `--disable` accept `--expect-report-id` and
  `--expect-sha256`, refuse the flags without an action, and refuse a malformed
  digest, covered by `tests/test_instruction_cli_binding.py`. The renderer view
  and shell operations remain open.
- Batch clean-baseline enrollment only after explicit confirmation, per the
  existing Guard contract.

### Phase 3 — Findings and diagnosis

- Incident list and diagnosis through `incidents --json`.
- "Resolve" for marker acknowledgement (unprivileged).
- Repair *plans* displayed with action IDs; applying them stays terminal-only
  until elevation is decided.

### Phase 4 — Privileged operations

Blocked on the elevation decision:

- **Option A (terminal handoff).** The app prepares the exact command, shows
  every parameter and the plan hash, and copies it. The user runs it. No new
  authority surface; the app cannot install anything.
- **Option B (fixed polkit client).** One unprivileged helper per operation
  (upgrade, maintenance, recovery, hook install) that revalidates its arguments
  and relies on desktop administrator authorization, mirroring
  `aurascan-intelligence-*` and the tray service clients. Larger, auditable, and
  must stay fail-closed when the helper or polkit is absent.

Upgrade and maintenance also need a plan identity in the CLI before either
option is safe: today `upgrade --json` prints a report with no hash to echo back
on apply.

## Non-goals

- An embedded terminal or a "run any command" field.
- Editing AuraScan source, rules, or policy from the app.
- Managing other packages, services, or files outside AuraScan's own surfaces.
- Storing OS credentials, sudo passwords, or root-owned settings in the app.
- Any root process, setuid component, or passwordless rule added for the app.

## Status

Phase 1 is implemented end to end:

- `aurascan settings --json` and `aurascan settings set-ai-key` (stdin), covered
  by `tests/test_ui_settings.py`;
- a Settings view in the renderer with a strict `aurascan-settings/1` parser,
  covered by `desktop/src/settings.test.ts`;
- four fixed shell operations (`refresh`, `openReport`, `readSettings`,
  `setAiKey`), with the credential validated and piped over stdin, covered by
  the shell and boundary tests;
- a self-test that reads settings, renders the view, and — when
  `AURASCAN_DESKTOP_SELF_TEST_WRITE=1` is set against a throwaway `HOME` —
  stores and re-reads one sentinel credential.

Phases 2–4 remain open.
