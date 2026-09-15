# AuraScan architecture

Status: maintained reference. Every number in this document is produced by an
offline tool, not estimated by hand.

Regenerate the measurements:

```bash
python tools/architecture_audit.py                # human-readable report
python tools/architecture_audit.py --strict       # same report, fails on invariant violations
python tools/architecture_audit.py --format json   # machine-readable inventory
python tools/architecture_audit.py --format markdown
```

The tool parses the package with `ast`. It never imports `aurascan`, never
executes package or candidate content, never runs a package manager and never
touches the network, so it is safe to run anywhere the tests run.

## Product model

AuraScan is a defensive layer for Arch-family systems that inspects untrusted
input *before* it gains authority. The product scope is intentionally broad —
package review, upgrade preflight, agent-control review, intelligence,
configuration drift, incident and recovery support, endpoint signals — but every
feature follows the same shape:

```
UNTRUSTED INPUT
    ↓
CAPTURE / NORMALIZATION
    ↓
STATIC ANALYSIS            (deterministic first)
    ↓
SECURITY EVIDENCE          (findings, coverage, uncertainty)
    ↓
POLICY / DECISION          (severity, blocking, review requirement)
    ↓
OPTIONAL USER ACTION / RECOVERY
```

Supporting planes:

| Plane | What it covers |
| --- | --- |
| Intelligence | Independently signed detection data, advisories, one captured snapshot per operation |
| Configuration / state | User config, caches, private reports, integrity manifests |
| UI / orchestration | CLI, tray, setup wizard, guided triage |
| Recovery | Optional recovery boot environment, image tooling, guarded repairs |
| Observability | Doctor checks, progress reporting, presenter explanations |

Two rules hold across every plane:

1. **Deterministic policy is authoritative.** AI is separately opt-in, advisory
   and raise-only. It cannot lower a finding, clear a blocker, or establish
   trust.
2. **Untrusted input is data, never instruction.** PKGBUILDs, install hooks,
   acquired source, agent-control files and model output are parsed, never
   executed and never treated as authority.

## Layers

Layers are assigned from repository structure by the audit tool. They describe
dependency direction; they are not a package reorganisation.

| Layer | Modules | Contents |
| --- | ---: | --- |
| `domain` | 4 | Evidence models and pure policy data: `core/models.py`, `core/risk.py`, `core/text_safety.py`, `core/update_policy.py` |
| `catalog` | 2 | Stable rule catalog and user-facing explanation templates: `core/rule_metadata.py`, `core/presenter.py` |
| `analysis` | 19 | `analyzers/` — static PKGBUILD, install-hook, provenance, remote-stage, npm, editor-task and bytecode analysis |
| `adapters` | 12 | Bounded platform boundaries: `core/trusted_tools.py`, `core/trusted_executable.py`, `core/archive.py`, `core/package_archive.py`, `core/source_acquisition.py`, `core/intelligence_transport.py`, `core/intelligence_crypto.py`, `core/cache.py`, `core/local_package_db.py`, `core/ai_provider.py`, `core/recovery_network.py`, `core/compatibility.py` |
| `application` | 25 | Orchestration and policy: `core/engine.py`, upgrade preflight, incidents, follow-up, agent, config drift, security audit, recovery planners, instruction guard logic |
| `recovery` | 3 | `core/recovery.py`, `core/recovery_boot.py`, `core/recovery_repairs.py` |
| `presentation` | 9 | Entry points and interactive surfaces: `cli.py`, `__main__.py`, `makepkg_wrapper.py`, `setup_wizard.py`, `core/updater_tray.py`, `core/intelligence_tray.py`, `core/instruction_cli.py`, `core/intelligence_cli.py`, `core/recovery_cli.py` |

Dependency direction:

```
domain / catalog   ←   analysis   ←   application   ←   presentation
                                            ↑
                                        adapters
```

- `domain` and `catalog` depend only on each other and the standard library
  (enforced by INV-012).
- `analysis` produces evidence; it does not execute processes (INV-001) and does
  not import UI entry points (INV-007).
- `adapters` own the dangerous capabilities: process execution, network access,
  archive extraction, privilege lookups, persistent state.
- `presentation` consumes application APIs and does not decide which rules exist
  (INV-011).

## Where side effects live

Measured capability ownership. Each list is pinned by a regression test in
`tests/test_architecture_audit.py`, so a new module that starts executing
processes or opening sockets fails the test until this document is updated.

| Capability | Modules | Notes |
| --- | ---: | --- |
| Process execution | 4 | `core/agent.py`, `core/local_package_db.py`, `core/package_archive.py`, `core/trusted_tools.py`. The last is the shared bounded runner; `core/trusted_executable.py` supplies the identity check it revalidates, but performs no execution itself. |
| Network access | 6 | `core/ai_provider.py`, `core/intelligence_transport.py`, `core/recovery_boot.py`, `core/security_audit.py`, `core/source_acquisition.py`, `core/upgrade_preflight.py` |
| Privilege-sensitive calls | 2 | `core/config.py`, `core/intelligence_cli.py` (ownership/UID lookups only, no privilege change) |
| Archive extraction | 1 | `core/archive.py` (`SafeArchiveExtractor`, bounded by bytes and entries) |
| SQLite state | 3 | `analyzers/history.py`, `core/cache.py`, `core/review.py` |
| Filesystem writes | 26 | Widespread by design; each path is bounded and reviewed at its call site |

Notably, **no analyzer executes a process** (INV-001). Analyzers obtain native
tool results through the trusted adapters, so the execution boundary stays in
one reviewable place.

## Hotspots

Ranked by mixed responsibility: `3 × capability categories + 2 × concern tags`,
plus one point each for ≥ 2000 lines or ≥ 15 dependents. The score exists to
order review, not to grade quality — a large cohesive module is not a defect.

| Module | Lines | Capabilities | Concerns | Fan-in | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| `core/upgrade_preflight.py` | 3142 | 4 | 6 | 5 | 25 |
| `core/agent.py` | 3741 | 4 | 5 | 3 | 23 |
| `core/incidents.py` | 4036 | 3 | 5 | 9 | 20 |
| `core/recovery.py` | 2350 | 3 | 5 | 3 | 20 |
| `core/security_audit.py` | 1544 | 4 | 4 | 3 | 20 |
| `core/updater_tray.py` | 1538 | 3 | 5 | 2 | 19 |
| `core/followup.py` | 2581 | 3 | 4 | 6 | 18 |
| `core/source_acquisition.py` | 2554 | 3 | 4 | 5 | 18 |
| `core/recovery_boot.py` | 1424 | 4 | 3 | 4 | 18 |
| `core/recovery_cli.py` | 1417 | 3 | 4 | 2 | 17 |

Most depended-on modules: `core/models.py` (30 importers), `core/ai_provider.py`
(13), `core/trusted_tools.py` (11), `core/text_safety.py` (10), `core/config.py`
(9).

Widest fan-out: `core/engine.py` (23 internal imports), `setup_wizard.py` (18),
`analyzers/deep_static.py` (15).

## Import cycles

Detected strongly connected components. A cycle is reported, not fatal: it is
still legal Python and can be intentional. Each one is tracked here so it is a
known decision rather than a surprise.

| Cycle | Modules | Assessment |
| --- | --- | --- |
| Recovery planner | `core.agent`, `core.config_drift`, `core.followup`, `core.incident_automation`, `core.incident_diagnostics`, `core.incident_repairs`, `core.incidents`, `core.upgrade_preflight` | Expected: these modules call each other's planners through function-local imports to avoid a heavier module-level graph. Candidate for a planner interface later. |
| Intelligence | `core.intelligence`, `core.intelligence_crypto`, `core.intelligence_store` | Expected: snapshot identity, verification and storage are one transaction. |
| Install-hook / provenance | `analyzers.repository_provenance`, `core.install_hook`, `core.source_acquisition` | Expected: declared-source filtering needs the hook reader and the acquisition snapshot. |
| Domain ↔ catalog | `core.models`, `core.presenter`, `core.risk`, `core.rule_metadata` | **Known coupling.** `core/models.py` renders terminal output by importing `core.presenter` inside a method, while `presenter` imports `models` at module level. This is the strongest remaining reason the domain layer cannot be read in isolation. |

## Architecture invariants

Encoded in `tools/architecture_audit.py` and enforced by
`python tools/architecture_audit.py --strict` in CI. `INVARIANT_ALLOWLIST` in the
tool is the only place an exception may be recorded, and each entry must carry a
reason.

| ID | Invariant |
| --- | --- |
| INV-001 | Static analyzers must not execute processes |
| INV-002 | Production code must not use `shell=True` or an implicit shell |
| INV-003 | Production code must not import training or model-research libraries |
| INV-004 | Production code must not import research tooling (`tools/`, `security-data`, model-lab) |
| INV-005 | Production runtime must stay standard library plus declared optional extras |
| INV-006 | Domain and catalog modules must not depend on AI provider modules |
| INV-007 | Core application code must not import UI entry points |
| INV-008 | Production code must not evaluate or unpickle dynamic data |
| INV-009 | Production code must not disable TLS verification |
| INV-010 | Domain and catalog modules must remain free of side effects |
| INV-011 | UI entry points must not contain rule IDs |
| INV-012 | Domain and catalog modules must depend only on domain and catalog |

What the invariants deliberately do **not** do: fail on module size, forbid
in-repo private names, or enforce a full layered architecture. The advisory
responsibility budget below reports unusually mixed modules as warnings only.

## Advisory responsibility budget

Reported by the audit, never fatal:

- modules over 2500 physical lines;
- modules with more than 5 capability categories;
- modules with more than 5 concern tags.

Current warnings: `core/instruction_guard.py` (8760 lines),
`analyzers/repository_provenance.py` (4555), `core/incidents.py` (4036),
`core/agent.py` (3741), `core/upgrade_preflight.py` (3142 lines, 6 concern tags),
`core/followup.py` (2581), `core/source_acquisition.py` (2554),
`setup_wizard.py` (2521).

## Decomposition log

### Stage 1 — trusted executable boundary

`core/upgrade_preflight.py` (3228 → 3142 lines) mixed the trusted-executable
identity check with upgrade orchestration, mirror repair, parsing and AI
advisory handling.

Extracted `core/trusted_executable.py`: `TrustedExecutable`,
`UnsafeUpgradeExecutable`, `capture_trusted_executable`,
`revalidate_trusted_executable` and the path/ownership validation behind them.

- **Responsibility sentence:** *bind a system tool to a trusted file identity and
  prove the file has not changed since capture.*
- **Public API:** unchanged. `upgrade_preflight` imports the names and keeps
  calling them through its namespace, so existing importers and the existing
  test substitution seam behave exactly as before.
- **Evidence for the seam:** `test_upgrade_preflight_imports_the_shared_trust_primitives`
  asserts the definitions moved and the imports remain.
- **Detection outcome:** unchanged — the full test suite passes, including the
  trusted-executable revalidation regressions, and the moved members are
  AST-identical to the originals apart from the documented rename.

### Deliberately not refactored yet

| Module | Why not yet |
| --- | --- |
| `core/instruction_guard.py` (8760) | Highest absolute risk: discovery, integrity manifests, private report state and triage UX in one file. Needs a characterisation-test layer over paging/enrollment state before any move. |
| `analyzers/repository_provenance.py` (4555) | Splitting magic classification from correlation is plausible, but the bounded-walk coverage rules are subtle and the fixture matrix is the contract. |
| `core/incidents.py` (4036) | Its cycle with the other planner modules must be designed first; extracting one member alone would leave the cycle in place. |
| `core/agent.py` (3741) | Command allowlisting, consent and execution are one security boundary; separating them without a policy/adapter interface risks weakening the fail-closed path. |

## Next targets

1. Break the `models` ↔ `presenter` cycle by removing rendering from the evidence
   model (highest clarity gain per unit of risk).
2. Give the incident/upgrade planner cycle a narrow interface so the eight-member
   component can be reviewed as a group.
3. Split `core/upgrade_preflight.py` further: mirror/repository repair (I/O plus
   privileged commands) from output parsing (pure functions).
4. Characterise Instruction Guard state transitions, then decompose by
   responsibility.

## Related documents

- [`SECURITY_BOUNDARIES.md`](SECURITY_BOUNDARIES.md) — trust boundaries and
  authority per surface.
- [`../AGENTS.md`](../AGENTS.md) — repository-wide safety contract.
- [`../DEVELOPING.md`](../DEVELOPING.md) — per-subsystem contributor contracts.
