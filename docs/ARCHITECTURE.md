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

Current measurement: **87 modules, 71,816 physical lines.**

| Layer | Modules | Contents |
| --- | ---: | --- |
| `domain` | 5 | Evidence and incident vocabulary: `core/models.py`, `core/text_safety.py`, `core/update_policy.py`, `core/redaction.py`, `core/incident_models.py` |
| `risk` | 1 | Risk aggregation over captured evidence: `core/risk.py` |
| `catalog` | 2 | Stable rule catalog and user-facing explanation templates: `core/rule_metadata.py`, `core/presenter.py` |
| `analysis` | 19 | `analyzers/` — static PKGBUILD, install-hook, provenance, remote-stage, npm, editor-task and bytecode analysis |
| `adapters` | 14 | Bounded platform boundaries: `core/trusted_tools.py`, `core/trusted_executable.py`, `core/archive.py`, `core/package_archive.py`, `core/source_acquisition.py`, `core/intelligence_transport.py`, `core/intelligence_crypto.py`, `core/cache.py`, `core/local_package_db.py`, `core/ai_provider.py`, `core/recovery_network.py`, `core/compatibility.py`, `core/state_file.py`, `core/bounded_process.py` |
| `application` | 25 | Orchestration and policy: `core/engine.py`, upgrade preflight, incidents, follow-up, agent, config drift, security audit, recovery planners, instruction guard logic |
| `recovery` | 3 | `core/recovery.py`, `core/recovery_boot.py`, `core/recovery_repairs.py` |
| `presentation` | 16 | Entry points, trays and renderers: `cli.py`, `__main__.py`, `makepkg_wrapper.py`, `setup_wizard.py`, `core/updater_tray.py`, `core/intelligence_tray.py`, `core/instruction_cli.py`, `core/intelligence_cli.py`, `core/recovery_cli.py`, `core/incident_cli.py`, plus the six rendering modules `core/scan_report_presenter.py`, `core/config_drift_presenter.py`, `core/incident_presenter.py`, `core/recovery_presenter.py`, `core/security_audit_presenter.py`, `core/upgrade_preflight_presenter.py` |

Dependency direction:

```
domain   ←   risk     ←   application   ←   presentation
domain   ←   catalog
```

- `domain` is the leaf layer: it depends on the standard library and on itself,
  and must not reach into risk, catalog, analysis, adapters, application,
  recovery or presentation code (INV-013). `core/incident_models.py` is the one
  domain module with intra-package imports today (`core.models` and
  `core.redaction`); `core/redaction.py`, `core/models.py`,
  `core/text_safety.py` and `core/update_policy.py` import nothing from the
  package.
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
  rules exist (INV-011). Rendering modules are sinks: none may appear in an
  import cycle (INV-015), and none may run a process, open the network, mutate
  the filesystem, touch privilege state or call an AI provider (INV-016).
  Command dispatch belongs here too, including flags that control another
  subsystem: `core/incident_cli.py` owns the automation-control flags that used
  to live in the incident workflow, and application code may not import it back
  (INV-007).

Renderer modules and their inputs:

| Module | Renders | Runtime imports |
| --- | --- | --- |
| `core/scan_report_presenter.py` | `ScanReport` | domain, catalog |
| `core/config_drift_presenter.py` | `ConfigDriftReport` | domain (also supplies `preview_diff`) |
| `core/incident_presenter.py` | `IncidentReport` | domain |
| `core/recovery_presenter.py` | `RecoveryReport` | `core/recovery` (ordering helper) |
| `core/security_audit_presenter.py` | `SecurityAuditReport` | domain |
| `core/upgrade_preflight_presenter.py` | `UpgradePreflightReport`, `UpgradeFailureDiagnosis` | domain |

A presenter that would form a cycle with the object it renders imports that type
under `if TYPE_CHECKING:` instead; the audit ignores type-checking blocks because
they are never executed, so a hint cannot hide a runtime dependency.

## Where side effects live

Measured capability ownership. Each list is pinned by a regression test in
`tests/test_architecture_audit.py`, so a new module that starts executing
processes or opening sockets fails the test until this document is updated.

| Capability | Modules | Notes |
| --- | ---: | --- |
| Process execution | 4 | `core/agent.py`, `core/local_package_db.py`, `core/package_archive.py`, `core/trusted_tools.py`. The last is the shared bounded runner; `core/trusted_executable.py` supplies the identity check it revalidates, but performs no execution itself. See the note below on injected runners. |
| Network access | 6 | `core/ai_provider.py`, `core/intelligence_transport.py`, `core/recovery_boot.py`, `core/security_audit.py`, `core/source_acquisition.py`, `core/upgrade_preflight.py` |
| Privilege-sensitive calls | 2 | `core/config.py`, `core/intelligence_cli.py` (ownership/UID lookups only, no privilege change) |
| Archive extraction | 1 | `core/archive.py` (`SafeArchiveExtractor`, bounded by bytes and entries) |
| SQLite state | 3 | `analyzers/history.py`, `core/cache.py`, `core/review.py` |
| Filesystem writes | 27 | Widespread by design; each path is bounded and reviewed at its call site. Stage 6 added `core/state_file.py` as the reviewer-visible owner of the atomic state write those callers share. |

**Capabilities trace call sites, not injected runners.** A module that receives
its runner as a parameter (`runner: Callable = subprocess.run`) or calls a
bounded helper such as `core/bounded_process.run_bounded_command` shows no
`process` tag, because the audit resolves call sites and imports rather than
data flow. The incident, repair, diagnostics, automation and setup paths execute
commands that way, so their execution authority is real and *under-reported* by
the table above. Treat the process count as a map of direct call sites, and read
`core/bounded_process.py` plus its callers for the bounded-execution boundary.

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
| Recovery planner | `core.agent`, `core.config_drift`, `core.followup`, `core.incident_automation`, `core.incident_diagnostics`, `core.incident_repairs`, `core.incidents`, `core.upgrade_preflight` | Expected: these modules call each other's planners through function-local imports to avoid a heavier module-level graph. Candidate for a planner interface later. Stage 5 removed the incident-to-automation *dispatch* edges and Stage 6 removed the repair-to-workflow vocabulary and infrastructure edges; the component is still eight members, reachable through `incident_repairs -> upgrade_preflight -> followup -> incidents`. The remaining debt is planner-to-planner coupling around repository repair. |
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
| INV-015 | Presentation modules must not participate in an import cycle |
| INV-016 | Presentation rendering modules must not perform dangerous operations |

What the invariants deliberately do **not** do: fail on module size, forbid
in-repo private names, or enforce a full layered architecture. The advisory
responsibility budget below reports unusually mixed modules as warnings only.

## Advisory responsibility budget

Reported by the audit, never fatal:

- modules over 2500 physical lines;
- modules with more than 5 capability categories;
- modules with more than 5 concern tags.

Current warnings: `core/instruction_guard.py` (8760 lines),
`analyzers/repository_provenance.py` (4555), `core/agent.py` (3741),
`core/incidents.py` (3241), `core/upgrade_preflight.py` (3044 lines, 6 concern
tags), `core/followup.py` (2585), `core/source_acquisition.py` (2554),
`setup_wizard.py` (2521), `core/updater_tray.py` (6 concern tags).

## Decomposition log

**Resolved in Stage 6:** the reverse half of `incidents <-> incident_repairs`. The
repair planner no longer imports the incident workflow for vocabulary or
infrastructure; the incident value types moved to the domain layer and three
shared helpers moved to dedicated adapters. The planner component is still eight
members, reachable now only through
`incident_repairs -> upgrade_preflight -> followup -> incidents`.

### Stage 6 — incident vocabulary and infrastructure left the workflow

`incident_repairs` imported nine symbols from `incidents`: four value types
(`IncidentReport`, `RepairAction`, `RepairResult`, plus `CommandOutput` and the
boot-target predicate), four low-level helpers (`atomic_write_json`,
`run_bounded_command`, `redact_incident_text`, `redact_structure`) and one path
constant (`INCIDENT_REPAIR_ROOT`). Tracing every consumer showed the ownership,
not just the direction, was wrong: the helpers were used by `updater_tray`,
`setup_wizard`, `recovery`, `recovery_repairs`, `incident_diagnostics` and
`incident_automation` as well, so the workflow was an accidental utility module.

| Symbol group | New owner | Responsibility sentence |
| --- | --- | --- |
| `IncidentReport`, `IncidentEvidence`, `IncidentFinding`, `CoredumpGroup`, `DiagnosticProbe`, `DiagnosticProbeResult`, `RepairAction`, `RepairResult`, `repair_action_covers_finding`, `valid_boot_target`, the incident state paths, schema/report IDs, severity/confidence order | `core/incident_models.py` (domain) | The incident domain's declarative surface: report value types and the state layout they live under |
| `redact_incident_text`, `redact_structure`, `correlation_token`, the redaction patterns | `core/redaction.py` (domain) | Privacy redaction: replace host-identifying and secret-bearing text with stable tokens |
| `atomic_write_json` | `core/state_file.py` (adapter) | Atomic writes of private state files with an explicit permission mode |
| `run_bounded_command`, `CommandOutput` | `core/bounded_process.py` (adapter) | Bounded subprocess capture for already-authorized commands |

- **Implemented verbatim:** all 38 moved definitions are AST-identical to the
  code they replace, including the timeout retry, the 127 error path, the
  `mkstemp`/`chmod`/`replace` sequence and every redaction pattern. No
  security-sensitive helper was rewritten while moving.
- **Direction enforced by layer, not by filename:** both vocabulary modules were
  added to the domain layer, so INV-013 now rejects a value or text module that
  imports the workflow, and INV-010 rejects one that gains a side effect. The two
  helper modules were classified as adapters, which is what makes their
  `fs_write`/process authority visible in the capability table.
- **Deliberately left alone:** the workflow still owns the persistence functions
  (`persist_incident_report`, `load_incident_report`, `list_incident_reports`),
  the configuration/env vocabulary, `MaintenanceCheckpoint` (it depends on the
  general `safe_int` helper) and `sanitize_error`. Moving them would have been a
  storage-layer redesign, not a dependency fix.
- **Duplication recorded, not merged:** `followup.redact_followup_text`,
  `recovery_boot.atomic_write`, `recovery_repairs._atomic_json`,
  `followup.atomic_write_private_json` and `config_drift.redact_text` remain
  separate implementations of the two concerns above. Stage 6 did not touch them
  (the non-goals exclude `followup` and the recovery subsystem);
  `core/redaction.py` and `core/state_file.py` are now the natural homes when
  those modules are next changed.
- **Capability visibility:** `fs_write` ownership grew from 26 to 27 modules
  because `core/state_file.py` became visible as the atomic-write owner. Process
  execution stayed at 4: the incident family executes through an injected runner,
  which the audit cannot see — documented above rather than papered over.

### Stage 5 — automation control flags left the incident workflow

The planner component contained an ambiguous edge: `incidents` imported
`incident_automation` and `incident_automation` imported `incidents`, so it was
impossible to say which subsystem was downstream. Characterizing all 57 import
statements inside the component showed that the `incidents` side of that pair
was **entirely command-line dispatch**: `run_incidents` parsed the incidents
command line and then serviced nine flags that belong to other subsystems
(`--set-auto-repair-policy`, `--safe-autopilot-enabled`, `--apply-request`,
`--enable-background-ai`, `--disable-background-ai`, `--auto-repair`,
`--background-ai-status`, `--capture-safe-autopilot`, `--background-assist`) by
lazy-importing `incident_automation` and `incident_repairs`.

- **Extracted `core/incident_cli.py`** (presentation layer):
  `run_incident_command()` parses the command line, routes those nine control
  flags, and otherwise delegates to `run_incidents()`. The branch bodies moved
  verbatim, including the `geteuid` root checks and the privileged helper's
  `validate_privileged_request_file` call, so refusals, exit codes and messages
  are unchanged.
- **`incidents.py` lost 8 of its 9 edges into `incident_automation`.** One
  deliberate orchestration edge remains: when resolving a pending marker the
  interactive workflow reuses a background plan that automation already
  produced (`load_reusable_background_plan`). That is a genuine
  planner-to-planner reuse, not dispatch glue, and it is documented rather than
  hidden.
- **Honest topology result:** the component is **still eight members**. Removing
  dispatch did not break the strongly connected component, because
  `followup <-> incidents` and `followup -> incident_automation -> incidents`
  still close cycles. The stage clarified ownership and edge direction; it did
  not reduce the component.
- **Direction enforced:** `core.incident_cli` now belongs to the audit's UI
  entry-point set, so INV-007 forbids any core application module from importing
  it back. A negative fixture asserts the violation is reported.
- **Deliberately not moved:** `run_incidents` itself. It is the interactive
  incident workflow (build report, plan repairs, review, confirm, apply,
  follow-up), not CLI glue; relocating it wholesale would have pushed
  orchestration and policy into presentation.
- **Not selected, recorded as debt:** the `incidents <-> incident_repairs` pair.
  Nine symbols travel from `incidents` to `incident_repairs`, and four of them
  (`atomic_write_json`, `run_bounded_command`, `redact_incident_text`,
  `IncidentReport`) are general utilities used far outside the incident
  subsystem. That is a misplaced-utility problem, not a direction problem:
  `incident_repairs` plans and executes actions, while `incidents` orchestrates
  them. Extracting a shared utility module would be the honest fix, and it is
  the recommended Stage 6 seam.
- **Evidence:** `tests/test_architecture_audit.py` (INV-007 fixture plus a seam
  direction test over the real package), `tests/test_incident_automation.py` and
  `tests/test_incidents.py` migrated to the new entry point with every existing
  behavior assertion kept.

### Stage 4 — presentation left the report classes

Six production classes still rendered themselves after Stage 3:
`ConfigDriftReport` (47 lines), `IncidentReport` (147), `RecoveryReport` (47),
`SecurityAuditReport` (67), `UpgradePreflightReport` (63) and
`UpgradeFailureDiagnosis` (13).

- **Compatibility finding:** all six methods were internal by the same standard
  as Stages 2 and 3 (no exported API, no documentation, CLI-only shipped
  surface). The only callers were in-package CLI entry points and tests.
- **Extracted five presenters** (see the renderer table above), carrying the
  rendering bodies verbatim. `preview_diff` moved with the config-drift renderer
  because it is a display formatter; `_check_summary_lines` and
  `_arch_audit_summary` moved as private formatting helpers that only the
  renderers used.
- **Direction enforced:** a first attempt had the subsystem modules import their
  presenters, which pulled three presenters *into* the planner component (8 → 11
  members) and created a new `security_audit` cycle. The audit caught it, so the
  presenters were made runtime-independent of their subsystems instead: types
  come from `if TYPE_CHECKING:` blocks and the few display constants are held in
  the presenter with an equality test against the engine value. The planner
  component is back to its original eight members.
- **Known debt (recorded, not changed):** the security-audit presenter derives
  its recommended-action line from finding severities and categories at render
  time. That is a policy-flavoured decision in presentation and is preserved
  byte-for-byte until it becomes a decided report field.
- **Evidence:** `tests/test_presentation_renderers.py` pins the removed methods,
  the entry-point defaults, the constant agreement, presenter purity and two
  negative fixtures; the subsystem suites exercise the new entry points and
  assert the rendered text unchanged.

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
| `core/incidents.py` (3825) | Stage 5 removed its CLI dispatch and its automation edges, so what is left is the interactive workflow. Its cycle with `followup`, `incident_repairs` and `incident_diagnostics` must be designed before another member moves. |
| `core/agent.py` (3741) | Command allowlisting, consent and execution are one security boundary; separating them without a policy/adapter interface risks weakening the fail-closed path. |

#### Planning and execution inside the repair module

`core/incident_repairs.py` holds both halves of the repair subsystem. Stage 6
classified every public function rather than splitting the file, because the
split was not what caused the cycle.

| Role | Functions |
| --- | --- |
| Planning | `plan_repair_actions` and the nine `plan_*` recipes (`plan_repository_restore`, `plan_stale_lock`, `plan_package_cache_cleanup`, `plan_kernel_headers`, `plan_dkms_autoinstall`, `plan_initramfs_rebuild`, `plan_service_restart`, `plan_exact_package_reinstall`), plus `make_action` and `repair_action_id` |
| Eligibility / policy | `is_background_safe_action`, `safe_background_repository_file`, `is_transient_application_unit`, `is_critical_unit`, `repair_action_covers_finding` (now in `incident_models`) |
| Authorization | The `geteuid()` gate in the autopilot entry point, `trusted_repair_commands`, and `execute_repair_request`'s request-file validation — plus `incidents`' root check and `incident_cli`'s dispatch checks |
| Execution | `apply_repair_plan`, `execute_repair_request`, `execute_one_repair`, `execute_background_safe_actions` and the ten `execute_*` recipes, `rollback_repository_repair` |
| Serialization | `repair_manifest_entry`, `backup_checksums`, `parse_repair_response`, `command_output_excerpt`, `refused`/`failed`/`applied` |
| Infrastructure | `sha256_file`, `path_size`, `make_run_id`, the pacman/version query helpers, `command_lines`, `command_text`, `journal_has_pattern` |

Assessment: the mixture is a readability and review-size cost, not an authority
problem. Authorization is checked at the entry points, eligibility is decided in
planning, and execution only ever runs actions that planning produced. The cycle
that keeps `incidents` and `incident_repairs` mutually reachable does not pass
through this internal split. Splitting the file is therefore **not** recommended
as the next seam.

## Next targets

1. The eight-member planner component (`agent`, `config_drift`, `followup`,
   `incidents`, `incident_*`, `upgrade_preflight`): give it a narrow interface so
   the cycle can be reviewed as a group rather than as eight mutual imports.
   Stage 6 removed the vocabulary and infrastructure half of the
   `incidents <-> incident_repairs` pair, so the remaining reachability runs
   through `incident_repairs -> upgrade_preflight -> followup -> incidents`.
   `upgrade_preflight` is therefore the next cycle edge worth separating: its
   mirror/repository repair capability is what pulls two planners into the loop.
   The planner/executor split inside `incident_repairs` is *not* recommended yet
   — see the classification above; it does not create the cycle.
2. **Partially done:** Stages 5 and 6 moved the `incidents` CLI runner and the
   shared helper ownership out of subsystem modules. `config_drift`,
   `security_audit` and `upgrade_preflight` still reach their presenter from
   inside their own CLI entry points. That edge is one-way and cycle-free, but
   it means CLI printing still lives in subsystem modules.
3. `core/upgrade_preflight.py` (3044 lines, 6 concern tags — the top hotspot):
   split mirror/repository repair (I/O plus privileged commands) from output
   parsing (pure functions). This is also the edge that keeps the planner cycle
   closed (`incident_repairs -> upgrade_preflight -> followup -> incidents`), so
   it is now both the largest hotspot and the highest-value next seam.
4. Five duplicate implementations of the two concerns Stage 6 extracted:
   `followup.redact_followup_text`/`redact_followup_structure`/`correlation_token`,
   `config_drift.redact_text`, `recovery_boot.atomic_write`,
   `recovery_repairs._atomic_json` and `followup.atomic_write_private_json`.
   They should converge on `core/redaction.py` and `core/state_file.py` when
   those modules are next changed.
5. Move the security-audit recommended-action decision out of the presenter and
   onto the report as a decided field.
6. Dead helpers found in earlier stages:
   `AnalysisResult.get_highest_severity()`, `AnalysisResult.blocks_installation()`
   and `findings_from_results()` still have no callers.
7. Characterise Instruction Guard state transitions, then decompose by
   responsibility.

## Related documents

- [`SECURITY_BOUNDARIES.md`](SECURITY_BOUNDARIES.md) — trust boundaries and
  authority per surface.
- [`../AGENTS.md`](../AGENTS.md) — repository-wide safety contract.
- [`../DEVELOPING.md`](../DEVELOPING.md) — per-subsystem contributor contracts.
