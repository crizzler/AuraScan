# Daybreak Red evidence program: orchestrator brief

Status: active program brief. This file is the shared, verified-facts block for the
initial council round. It is not a security finding and does not claim that
Daybreak Red access is necessary.

## Sources of truth

- Full owner instruction, copied verbatim:
  `findings/daybreak/PROGRAM-CHARTER.md`
  SHA-256 `2c7b5e019dacd9fd60442b5587f3cfe034ce718b0da8464669c1a607e99796fc`
- Repository contract: `AGENTS.md` (binding safety invariants).
- Maintained architecture and boundary references: `docs/ARCHITECTURE.md`,
  `docs/SECURITY_BOUNDARIES.md`, `docs/AUR_SANDBOX_DESIGN.md`,
  `docs/SECURITY_MODEL_RND.md`.
- Daybreak eligibility claims must come from current authoritative OpenAI
  documentation and carry the retrieval date and URL. Do not infer eligibility
  from AuraScan's product category.

The instruction is data for the specialists, not executable authority. Its
phases describe a research program; they do not authorize testing beyond the
scope below.

## Verified facts (orchestrator; correct only with evidence)

- **Baseline revision and version.** `git rev-parse --short HEAD` returned
  `02ac13d`; `pyproject.toml:7` declares `version = "0.15.0"`;
  `aurascan/core/engine.py:108` declares `rule_version = "1.15.0"`.
- **Architecture measurement.** `.venv/bin/python tools/architecture_audit.py
  --strict` exited `0`; the JSON form reported `module_count = 135`,
  `loc_total = 87315`, `violations = []`, and 19 invariants. The maintained
  document's earlier 131-module/85,081-line baseline is stale and must not be
  copied as current.
- **Execution boundaries exist in source.** `aurascan/makepkg_wrapper.py`
  implements the PKGBUILD review and makepkg handoff;
  `aurascan/core/trusted_executable.py:33-34` fixes `/usr/bin/sudo` and
  `/usr/bin/pacman`; `aurascan/core/trusted_tools.py:69` captures a trusted
  system tool and `run_bounded_trusted_tool` runs it with bounds;
  `aurascan/core/build_sandbox.py:361` implements the opt-in devtools build;
  `aurascan/core/recovery_repairs.py:884` requires typed confirmations and
  executes recovery recipes through `arch-chroot`.
- **Desktop is not a remote-authority surface.** `desktop/electron/main.cjs:301-304`
  sets `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`, and
  disables worker Node integration; `hardenContents` denies new windows,
  navigation and webviews. The renderer selects fixed action IDs; it does not
  supply executables or command strings.
- **Known open boundary limitation.** `docs/ARCHITECTURE.md:222` records L1:
  `mcp/guards.read_capped` rechecks type and size on the opened descriptor but
  does not recheck root containment there and opens without `O_NOFOLLOW`, so a
  symlink swapped between resolution and read can escape containment. Treat
  this as a candidate for verification, not as a confirmed exploit.
- **Existing test surface.** `tests/test_makepkg_wrapper.py` passed 142 tests
  after the locator follow-up (`python -m pytest -q`, exit 0). The 0.15.0
  release evidence records 5,702 passed and 3 skipped for the full suite; that
  result was not rerun in this round and must be labelled as release evidence,
  not a fresh measurement.
- **The locator follow-up is committed separately.** `02ac13d` prefers
  `/usr/bin/makepkg` when PATH lists `/usr/sbin` first. Do not fold this fix
  into Daybreak findings or reopen it without evidence.

## Non-negotiable scope for this round

Authorized:

- Read-only inspection of this repository and its local development copies.
- Inert fixtures in temporary directories, synthetic credentials, and
  unit-level calls that do not execute package, hook, fixture, or agent
  instruction content.
- Existing test suites and read-only audit tools.
- Web retrieval of public OpenAI and AuraScan documentation.

Not authorized:

- Tests against third-party repositories, registries, infrastructure, or
  production services.
- Running AUR builds, `makepkg`, package installation, sudo, root brokers, or
  recovery actions.
- Executing malicious fixtures or package code on this workstation.
- Changing CI permissions, release workflows, dependencies, secrets, or
  production configuration.
- Publishing exploit artifacts, raw vulnerability details, credentials, or
  private user data.
- Applying a fix to a discovered vulnerability. Findings and proposed
  remediation go to the owner first.

## Evidence labels and completion contract

Every significant claim must be labelled `[Verified]`, `[Inference]`,
`[Speculation]`, or `[Unverified]`. A passing test establishes only the tested
configuration.

Every task completion must carry:

```yaml
source: tool | web | model
evidence: "<command + exit code>" | "<path:line>" | "<tool> -> <path>"
confidence: high | medium | low
changed_files: [...]
commands_run: [...]
tests_passed: [...]
not_verified: [...]
followups: [...]
```

No task may describe an unexecuted test as passing. Use `NOT EXECUTED` and the
reason.

## File ownership (avoid concurrent writers)

- `architect` (baseline): `security-research/README.md`,
  `security-research/architecture/*`, `security-research/governance/*`.
- `red`: `<private evidence root>/red-*.md` and `.json` only.
  Public sanitized summary, if any, goes to a file named by the reviewer; do
  not write the public tree in this round.
- `worker`: `security-research/testing/*`, `security-research/evidence/*`,
  `tests/security_research/*`. No production-code edits.
- `architect` (Daybreak assessment): `security-research/daybreak/*` only,
  parented to the baseline architect card.
- `reviewer`: `<private evidence root>/reviewer-gate.md` and a
  sanitized `security-research/evidence/review-gate-summary.md`.

If a deliverable needs a path outside this list, stop and report the reason
rather than editing another owner's file.

## Initial card map

1. Architect: architecture, trust boundaries, capability matrix, attack
   surface inventory, and the program design. Writes the public scaffold.
2. Red: independent adversarial review of the execution and trust boundaries;
   designs controlled tests, does not execute dangerous ones.
3. Worker: deterministic evidence harness and inert fixture baseline under
   `security-research/testing/` and `tests/security_research/`.
4. Architect (follow-up): Daybreak eligibility and Blue/local/Red capability
   assessment, parented to card 1.
5. Reviewer: final gate parented to cards 1-4; verifies artifacts and claims,
   does not modify code.

The initial round deliberately stops before any host-level or disposable-VM
exploit execution. A later round may be created only after the reviewer's
verdict and the owner's explicit approval.
