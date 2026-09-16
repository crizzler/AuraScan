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

Current measurement: **77 modules, 71,442 physical lines.**

| Layer | Modules | Contents |
| --- | ---: | --- |
| `domain` | 3 | Evidence vocabulary — the leaf of the graph: `core/models.py`, `core/text_safety.py`, `core/update_policy.py` |
| `risk` | 1 | Risk aggregation over captured evidence: `core/risk.py` |
| `catalog` | 2 | Stable rule catalog and user-facing explanation templates: `core/rule_metadata.py`, `core/presenter.py` |
| `analysis` | 19 | `analyzers/` — static PKGBUILD, install-hook, provenance, remote-stage, npm, editor-task and bytecode analysis |
| `adapters` | 12 | Bounded platform boundaries: `core/trusted_tools.py`, `core/trusted_executable.py`, `core/archive.py`, `core/package_archive.py`, `core/source_acquisition.py`, `core/intelligence_transport.py`, `core/intelligence_crypto.py`, `core/cache.py`, `core/local_package_db.py`, `core/ai_provider.py`, `core/recovery_network.py`, `core/compatibility.py` |
| `application` | 25 | Orchestration and policy: `core/engine.py`, upgrade preflight, incidents, follow-up, agent, config drift, security audit, recovery planners, instruction guard logic |
| `recovery` | 3 | `core/recovery.py`, `core/recovery_boot.py`, `core/recovery_repairs.py` |
| `presentation` | 10 | Entry points and rendering surfaces: `cli.py`, `__main__.py`, `makepkg_wrapper.py`, `setup_wizard.py`, `core/updater_tray.py`, `core/intelligence_tray.py`, `core/instruction_cli.py`, `core/intelligence_cli.py`, `core/recovery_cli.py`, `core/scan_report_presenter.py` |

Dependency direction:

```
domain   ←   risk     ←   application   ←   presentation
domain   ←   catalog
```

- `domain` is the leaf: it depends on the standard library only, and has no
  intra-package imports at all today. It must not reach into risk, catalog,
  analysis, adapters, application, recovery or presentation code (INV-013).
- `risk` aggregates captured evidence into a `RiskSummary`. It may use domain
  modules and itself, and nothing higher (INV-014).
- `catalog` may use domain modules and itself (INV-012).
- `analysis` produces evidence; it does not execute processes (INV-001) and does
  not import UI entry points (INV-007).
- `adapters` own the dangerous capabilities: process execution, network access,
  archive extraction, privilege lookups, persistent state.
- `application` assembles reports and decides outcomes: `core/engine.py` builds
  the `ScanReport` and asks `RiskEngine` for the summary.
- `presentation` consumes application and domain APIs and does not decide which
  rules exist (INV-011).

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

Most depended-on modules: `core/models.py` (31 importers), `core/ai_provider.py`
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

No cycle contains the evidence model, and the domain layer is now a leaf with no
intra-package imports at all.

**Resolved in Stage 2:** the four-module `{core.models, core.presenter, core.risk,
core.rule_metadata}` component. The evidence model used to import the terminal
presenter to render itself; rendering now lives in
`core/scan_report_presenter.py`.

**Resolved in Stage 3:** the residual `{core.models, core.risk}` component.
`AnalysisResult.to_report()` imported `RiskEngine` to assemble a report, which
made the evidence vocabulary depend on the risk service. Report assembly is an
application-layer responsibility — `core/engine.py` already does it — so the two
uncalled methods were removed rather than relocated.

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
| INV-006 | Domain, risk and catalog modules must not depend on AI provider modules |
| INV-007 | Core application code must not import UI entry points |
| INV-008 | Production code must not evaluate or unpickle dynamic data |
| INV-009 | Production code must not disable TLS verification |
| INV-010 | Domain, risk and catalog modules must remain free of side effects |
| INV-011 | UI entry points must not contain rule IDs |
| INV-012 | Catalog modules must depend only on domain and catalog |
| INV-013 | Domain evidence modules must not depend on risk, catalog or presentation |
| INV-014 | Risk computation modules must depend only on domain and risk |

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

### Stage 3 — the evidence model stops assembling reports

With the presenter gone, the evidence model still borrowed `RiskEngine` inside
`AnalysisResult.to_report()` (430 → **416** lines), which kept a smaller
`models` <-> `risk` cycle alive.

- **Compatibility finding:** `AnalysisResult.to_report()` and
  `AnalysisResult.to_dict(package_name, package_version)` were internal *and
dead*: zero callers in `aurascan/`, `tests/`, `tools/`, `contrib/` or
`packaging/`, no dynamic `getattr` use, and no mention in any user or developer
document. `AnalysisResult` is used throughout the analyzers purely as the
return-value container the engine reads (`is_safe`, `findings`).
- **Root cause of the survival:** the layer taxonomy classified `core/risk.py` as
`domain`, so `models → risk` was not an upward edge and INV-013 did not fire.
The taxonomy, not the edge, hid the cycle.
- **Change:** removed the two dead methods instead of relocating them. Report
assembly already lives in the application layer (`core/engine.py` builds the
`ScanReport` and calls `self.risk_engine.evaluate(...)`), so moving the methods
to a new service would have created a module with no callers — mechanical
acyclic-graph editing rather than a real seam.
- **Cycle removed:** no strongly connected component contains `models` any more;
`core/models.py` now has **no intra-package imports at all** and remains the most
depended-on module (31 importers).
- **Taxonomy corrected:** `core/risk.py` moved to its own `risk` layer, and
INV-013 was rewritten to the real rule (domain may depend on domain only) plus
INV-014 for the risk layer. INV-013 now reproduces the removed edge if it
returns.
- **Evidence:** `tests/test_models_and_risk.py` pins `AnalysisResult`'s retained
container semantics and the application-layer assembly path;
`tests/test_architecture_audit.py` asserts the layer rule (not an exact import
list) and includes a synthetic regression for a domain-to-risk edge.

Dependency shape, before and after:

```
BEFORE

  core.models.AnalysisResult.to_report
        │  (lazy import)
        ▼
  core.risk.RiskEngine
        │  (top-level import)
        ▼
  core.models  (Finding, RiskSummary, Severity, ...)
  SCC: {core.models, core.risk}

AFTER

  core.engine          core.risk
        ├──▶ core.models     └──▶ core.models
        └──▶ core.risk
  SCC: none containing core.models
```
presentation of a scan report: `ScanReport.render_terminal` owned 99 lines of
ANSI colour, English wording and update-scan policy prose, and imported
`core.presenter` inside the method to do it.

- **Compatibility finding:** `ScanReport.render_terminal` was **not** a
documented or supported API. `aurascan/__init__.py` exports nothing, no module
defines `__all__`, no README/developer doc or release note referenced the
method, and the shipped interface is the `aurascan` and `aurascan-makepkg`
console scripts. All production callers were in-package, and the only
out-of-package consumer (`tools/aur_warning_tune.py`) builds a `ScanReport`
without rendering it. It was therefore removed outright rather than kept as a
shim, which would have preserved the very cycle being removed.
- **Extracted `core/scan_report_presenter.py`:** `render_scan_report(report,`
`use_color=True, verbose=False)`, carrying the rendering body verbatim.
- **Responsibility sentence:** *turn a captured scan report into terminal text.*
- **Callers updated:** four in `core/engine.py`, plus test call sites across
eight test files.
- **Cycle removed:** the four-module SCC became a two-module one; `presenter` and
`rule_metadata` left the cycle entirely.
- **Invariant tightened:** INV-012 was narrowed to catalog modules, and INV-013
was added to forbid any domain-to-catalog or domain-to-presentation edge. INV-013
reproduces the original defect if it is reintroduced.
- **Evidence:** `tests/test_scan_report_rendering.py` records full golden output
for eight scenarios; the goldens were captured before the move and are
byte-identical after it, with only the single `render` indirection changed.

Import graph around the evidence model, before and after:

```
BEFORE

  core.models ──▶ core.presenter  ◀── cycle with the edge below
  core.presenter ──▶ core.models
  core.models ──▶ core.risk
  core.risk ──▶ core.models
  core.models ──▶ core.text_safety
  core.rule_metadata ──▶ core.models
  SCC: {core.models, core.presenter, core.risk, core.rule_metadata}

AFTER

  core.models ──▶ core.risk
  core.risk ──▶ core.models
  SCC: {core.models, core.risk}
```

Both direction changes are visible in the same measurement: the evidence model
lost two outgoing edges (`presenter`, `text_safety`) and the cycle shrank from
four modules to two.

Module responsibilities:

| Module | Before | After |
| --- | --- | --- |
| `core/models.py` | Evidence vocabulary **and** terminal rendering of a scan report | Evidence vocabulary only (430 lines, 19 public symbols) |
| `core/presenter.py` | Rule explanation templates | Unchanged |
| `core/scan_report_presenter.py` | — | Terminal rendering of a scan report (134 lines, 1 public symbol) |
| `core/engine.py` | Called `report.render_terminal(...)` | Calls `render_scan_report(report, ...)` |

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

1. The eight-member planner component (`agent`, `config_drift`, `followup`,
   `incidents`, `incident_*`, `upgrade_preflight`): give it a narrow interface so
   the cycle can be reviewed as a group rather than as eight mutual imports.
2. `core/upgrade_preflight.py` (3142 lines, 6 concern tags — the top hotspot):
   split mirror/repository repair (I/O plus privileged commands) from output
   parsing (pure functions).
3. Apply the Stage 2 seam to the remaining report classes that still own their
   own `render_terminal` (`config_drift`, `incidents`, `recovery`,
   `security_audit`, `upgrade_preflight`) so presentation lives in one layer
   everywhere.
4. Dead helper methods discovered during Stage 3: `AnalysisResult.get_highest_severity()`,
   `AnalysisResult.blocks_installation()` and `findings_from_results()` also have
   no callers. They carry no dependency, so they were left alone, but the
   evidence model should not advertise policy helpers that nothing uses.
5. Characterise Instruction Guard state transitions, then decompose by
   responsibility.

## Related documents

- [`SECURITY_BOUNDARIES.md`](SECURITY_BOUNDARIES.md) — trust boundaries and
  authority per surface.
- [`../AGENTS.md`](../AGENTS.md) — repository-wide safety contract.
- [`../DEVELOPING.md`](../DEVELOPING.md) — per-subsystem contributor contracts.
