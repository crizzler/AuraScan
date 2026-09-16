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

Current measurement: **91 modules, 72,084 physical lines.**

| Layer | Modules | Contents |
| --- | ---: | --- |
| `domain` | 6 | Evidence and upgrade vocabulary: `core/models.py`, `core/text_safety.py`, `core/update_policy.py`, `core/redaction.py`, `core/incident_models.py`, `core/upgrade_models.py` |
| `risk` | 1 | Risk aggregation over captured evidence: `core/risk.py` |
| `catalog` | 2 | Stable rule catalog and user-facing explanation templates: `core/rule_metadata.py`, `core/presenter.py` |
| `analysis` | 19 | `analyzers/` — static PKGBUILD, install-hook, provenance, remote-stage, npm, editor-task and bytecode analysis |
| `adapters` | 16 | Bounded platform boundaries: `core/trusted_tools.py`, `core/trusted_executable.py`, `core/archive.py`, `core/package_archive.py`, `core/source_acquisition.py`, `core/intelligence_transport.py`, `core/intelligence_crypto.py`, `core/cache.py`, `core/local_package_db.py`, `core/ai_provider.py`, `core/recovery_network.py`, `core/compatibility.py`, `core/state_file.py`, `core/bounded_process.py`, `core/repository_state.py`, `core/repository_repair.py` |
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
  `core/text_safety.py`, `core/update_policy.py` and `core/upgrade_models.py`
  import nothing from the package.
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
| `core/upgrade_preflight.py` | 2607 | 4 | 6 | 2 | 25 |
| `core/agent.py` | 3751 | 4 | 5 | 3 | 23 |
| `core/updater_tray.py` | 1540 | 3 | 6 | 2 | 21 |
| `core/incidents.py` | 3237 | 3 | 5 | 7 | 20 |
| `core/recovery.py` | 2303 | 3 | 5 | 4 | 20 |
| `core/security_audit.py` | 1465 | 4 | 4 | 3 | 20 |
| `core/incident_automation.py` | 707 | 3 | 5 | 5 | 19 |
| `core/recovery_boot.py` | 1424 | 4 | 3 | 4 | 18 |
| `core/source_acquisition.py` | 2554 | 3 | 4 | 5 | 18 |
| `core/incident_repairs.py` | 1144 | 3 | 4 | 5 | 17 |

Most depended-on modules: `core/models.py` (36 importers), `core/ai_provider.py`
(13), `core/text_safety.py` (13), `core/trusted_tools.py` (11), `core/config.py`
(10).

Widest fan-out: `core/engine.py` (24 internal imports), `setup_wizard.py` (20),
`core/incidents.py` (18).

## Import cycles

Detected strongly connected components. A cycle is reported, not fatal: it is
still legal Python and can be intentional. Each one is tracked here so it is a
known decision rather than a surprise.

| Cycle | Modules | Assessment |
| --- | --- | --- |
| Agent and follow-up | `core.agent`, `core.followup` | Two members, down from six. Stages 5–9 removed the dispatch, vocabulary, repository-interpretation, follow-up-refresh and upgrade-value edges; Stage 10 moved the incident-family adapters out and Stage 11 moved the config-drift adapters out. What is left is bidirectional orchestration: the framework's in-session `/agent` escalation command imports the agent workflow, while the agent runs its sessions through the framework. |
| Incident planners | `core.incident_automation`, `core.incident_diagnostics`, `core.incidents` | Expected and deliberate: the incident workflow, its diagnostics planner and its automation layer share report state and repair vocabulary. Nothing outside that group needs to enter it. |
| Intelligence | `core.intelligence`, `core.intelligence_crypto`, `core.intelligence_store` | Expected: snapshot identity, verification and storage are one transaction. |
| Install-hook / provenance | `analyzers.repository_provenance`, `core.install_hook`, `core.source_acquisition` | Expected: declared-source filtering needs the hook reader and the acquisition snapshot. |

No cycle contains the evidence model, and the domain layer only ever depends on
itself: five of its six modules import nothing from the package at all, and
`core/incident_models.py` uses only `core.models` and `core.redaction`.

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
| INV-017 | Platform adapters must not depend on application workflows |

What the invariants deliberately do **not** do: fail on module size, forbid
in-repo private names, or enforce a full layered architecture. The advisory
responsibility budget below reports unusually mixed modules as warnings only.

## Advisory responsibility budget

Reported by the audit, never fatal:

- modules over 2500 physical lines;
- modules with more than 5 capability categories;
- modules with more than 5 concern tags.

Current warnings: `core/instruction_guard.py` (8760 lines),
`analyzers/repository_provenance.py` (4555), `core/agent.py` (3751),
`core/incidents.py` (3237), `core/upgrade_preflight.py` (2607 lines, 6 concern
tags), `core/source_acquisition.py` (2554), `setup_wizard.py` (2521),
`core/updater_tray.py` (6 concern tags). `core/followup.py` (2066) left this list
in Stage 11.

## Decomposition log

**Resolved in Stage 11:** the generic follow-up framework no longer imports the
config-drift lifecycle. `context_from_config_drift` and
`build_config_drift_runtime` moved into `core/config_drift.py`, and the one piece
of drift behavior the framework still hosted — preparing the fix an upgrade
session may apply — became `prepare_config_drift_remediation`, supplied back in
through a provider. `followup -> config_drift` is gone; `config_drift` left the
planner component, leaving `{agent, followup}`.

### Stage 11 — the config-drift lifecycle owns its own follow-up adapters

`followup` imported `config_drift` behavior in three places, and `config_drift`
called the framework back in four, so the two modules were mutually reachable.
Reading both directions showed the reverse edge was the accidental one: a
generic framework hosted a concrete lifecycle's adapters.

| Direction | Kind | Outcome |
| --- | --- | --- |
| `config_drift -> followup` | lifecycle orchestration (`offer_followup`, `prompt_with_followup`, `FollowUpRuntime`) | kept: the workflow offers and embeds its own session through the framework |
| `followup -> config_drift` | misplaced lifecycle adapters | removed: the adapters moved into `core/config_drift.py` |
| `followup -> config_drift_presenter` | presentation owned by the lifecycle | removed: the rendered plan is printed by `prepare_config_drift_remediation`, the lifecycle's own module |

- **Moved verbatim:** `context_from_config_drift` (61 significant body lines) and
  `build_config_drift_runtime` (70) now live in `core/config_drift.py`. An
  AST comparison against the pre-stage revision shows identical parameter lists
  and byte-identical statements: only the import statements moved to the local
  style and the `FollowUpContext`/`FollowUpRuntime` annotations became strings.
  Those strings are not cosmetic — a lazily imported name used as a bare
  annotation raises `NameError` on Python 3.8, where annotations are evaluated
  when the `def` runs, while CPython 3.14 defers them and hides the defect. A
  static rule in the architecture tests now fails on any production annotation
  whose name the module has not bound, and the rule is itself exercised against
  a fixture so it cannot silently pass. `config_drift`'s four call sites resolve
  the functions locally, so no caller on that side changed shape.
- **One new seam:** `prepare_config_drift_remediation(root, *, stdout)` returns a
  `ConfigDriftRemediation` with the re-derived `action_ids` and a `safe` flag,
  and applies them by running the guarded assistant with `--no-ai --yes
  --action-id …` — the exact command the framework used to build inline. The
  decision of *what* is verified and *whether* a fix may be a safe default now
  lives with drift policy instead of inside the framework.
- **Supplied, not imported:** `build_default_runtime`, `run_ask`, `run_agent` and
  `build_upgrade_runtime` accept `config_drift_runtime_provider` and
  `config_drift_remediation_provider`. `cli.py` supplies both for `ask`/`agent`
  sessions and `upgrade_preflight`'s three runtime sites supply the remediation
  provider.
- **Fail closed:** without the runtime provider a config-drift context degrades
  to facts only — the session prints that the requested operation is not
  executable from the retained context and generates no command. Without the
  remediation provider the framework drops the drift action instead of applying
  stale state, and says the fix could not be re-prepared. Both paths have tests,
  as does the prepared-fix path that now runs through the lifecycle.
- **Drift authority stayed put:** discovery, classification, plan validation,
  backups, redaction and the applied command are still owned by
  `core/config_drift.py`; the framework coordinates supplied operations only.
- **Honest limit:** the framework still hosts the upgrade session's repository
  and kernel-module action adapters (`build_upgrade_runtime` imports
  `repository_repair` and `kernel_module_autopilot`), so `followup` is not yet a
  pure framework. Those edges stay one-way and cycle-free; they are the Stage 12
  candidate together with `followup -> agent`.

**Resolved in Stage 10:** the generic follow-up framework no longer imports any
incident module. The incident-family adapters moved into
`core/incident_followup.py` and are supplied to the framework by its callers, so
the incident planners left the planner component and the remaining cycle is
`{agent, config_drift, followup}`.

### Stage 10 — framework and lifecycle adapters separated

`followup` imported the incident family in four places:
`context_from_saved_incident` / `context_from_latest_saved_incident` (retained
results), `build_incident_runtime` (fresh state, diagnostic probes, repair
application, marker acknowledgement) and the incident half of
`build_maintenance_runtime` (maintenance re-collects an incident report). Reading
them showed the same shape every time: the *framework* hosted concrete lifecycle
adapters, so the generic module needed the lifecycle workflows.

| Direction | Kind | Outcome |
| --- | --- | --- |
| `incidents -> followup` | lifecycle orchestration | kept: the workflow offers and embeds its own session through the framework |
| `followup -> incidents`, `-> incident_automation`, `-> incident_diagnostics`, `-> incident_repairs` | misplaced lifecycle adapters | removed: the adapters live in `core/incident_followup.py` |

- **Moved verbatim:** `context_from_saved_incident`,
  `context_from_latest_saved_incident`, `build_incident_runtime` and
  `build_maintenance_runtime` (396 lines) now live in
  `core/incident_followup.py`, together with `build_incident_followup_runtime`
  (one entry point that dispatches incident vs maintenance) and
  `load_incident_followup_context`. The module imports the incident workflow, its
  diagnostics planner and its repair planner; none of them import it back.
- **Supplied, not imported:** the framework's `run_ask`, `build_default_runtime`
  and the agent take `incident_context_provider` and
  `incident_runtime_provider`; `cli.py` supplies them for retained contexts and
  `incident_cli.py` supplies the runtime provider for live sessions. This is the
  same provider pattern Stage 8 introduced for the upgrade refresh.
- **Fail closed:** without a provider the incident workflow builds no follow-up
  context or runtime, and an incident context received by the framework degrades
  to facts only — no probes and no repairs run from stale state. Two tests pin
  both paths.
- **Incident authority stayed put:** report collection, marker state, repair
  planning/execution, eligibility and root checks are still owned by
  `incidents`, `incident_diagnostics`, `incident_repairs` and
  `incident_automation`; the framework only coordinates the operations they
  supply.
- **Not in scope, recorded:** `build_config_drift_runtime` and
  `build_upgrade_runtime` remained in the framework at this point. Stage 11 moved
  the config-drift adapter into its lifecycle; `build_upgrade_runtime` and its
  `repository_repair`/`kernel_module_autopilot` imports are recorded there as the
  remaining adapter of the same shape.

### Stage 9 — the inert upgrade values became a domain module

`incidents` imported exactly two symbols from `upgrade_preflight`:
`SystemSnapshot` and `UpgradePlan`. The flow is not upgrade analysis at all: the
incident workflow builds a snapshot from its own bounded collection and passes it,
with an empty plan, to `kernel_module_autopilot.build_kernel_module_check(...)`,
whose findings become `INC-DKMS` evidence. No upgrade policy, severity decision,
network call or process capability travelled with those types.

| Symbol | Old owner | New owner | Responsibility |
| --- | --- | --- | --- |
| `UpgradePackage` | `upgrade_preflight` | `core/upgrade_models.py` (domain) | one planned package change |
| `ForeignPackageInfo` | `upgrade_preflight` | `core/upgrade_models.py` (domain) | captured foreign-package metadata |
| `UpgradePlan` | `upgrade_preflight` | `core/upgrade_models.py` (domain) | planned transaction state (`available`, `package_names`, `to_dict`) |
| `SystemSnapshot` | `upgrade_preflight` | `core/upgrade_models.py` (domain) | observed system state |
| `SystemSnapshot.collect` | classmethod on the value | `upgrade_preflight.collect_system_snapshot` | observing the machine needs process execution and the trusted pacman identity, so it stayed in the workflow |

- **Inertness verified before moving:** field defaults, empty and populated
  `to_dict` projections, `available`, `package_names` and the trusted-executable
  projection are identical to the pre-Stage-9 definitions. `UpgradePlan` still
  carries captured executable identities, but only as a `TYPE_CHECKING`
  annotation: the module runs nothing, and it imports nothing at runtime.
- **Not moved:** `UpgradeFinding`, `UpgradeOptions`, `UpgradeConfig` and
  `UpgradeFailureDiagnosis`. They are produced by preflight analysis and policy
  (severity, blocking, recommendation), so they belong with the code that decides
  them, not with the inputs those decisions consume.
- **No AI involvement:** the borrowed values never touch the advisory path; the
  AI advisory block stays in `upgrade_preflight` as Stage 8 left it.
- **Topology:** `upgrade_preflight` left the planner component, which is now six
  members (`agent`, `config_drift`, `followup`, `incident_automation`,
  `incident_diagnostics`, `incidents`). Its remaining inbound edges are
  presentation only (`cli.py`, `setup_wizard.py`).

### Stage 8 — the upgrade lifecycle supplies its own follow-up refresh

`followup` imported `upgrade_preflight` in exactly one place: the upgrade
lifecycle adapter `build_upgrade_runtime` re-ran `run_upgrade_preflight` inside
its `refreshed_report()` helper, so that the follow-up session could revalidate
retained support actions against fresh state. The reverse direction is
deliberate orchestration: `run_upgrade` builds the follow-up context and offers
or embeds the session at four decision points, which is the same pattern
`incidents` and `config_drift` use.

| Direction | Kind | Why it existed | Outcome |
| --- | --- | --- | --- |
| `upgrade_preflight -> followup` | orchestration | the upgrade workflow offers and embeds the follow-up session (`context_from_upgrade`, `build_upgrade_runtime`, `offer_followup`, `prompt_with_followup`) | kept: it is the lifecycle owner driving the shared session |
| `followup -> upgrade_preflight` | refresh / revalidation | `build_upgrade_runtime` re-ran the preflight to refresh retained state before acting | removed: the refresh operation is now a function-valued parameter |

- **What moved:** `refresh_upgrade_preflight(context, *, runner, which, urlopen)`
  now lives in `upgrade_preflight` with the exact body of the old
  `refreshed_report()`; `build_upgrade_runtime` takes
  `refresh_report: Optional[Callable]` and calls it with the session's own hooks;
  `build_default_runtime`, `run_ask` and `run_agent` pass an optional
  `refresh_upgrade_report`, which `cli.py` supplies as
  `refresh_upgrade_preflight`. The returned `options` value was unused, so the
  contract carries only the report.
- **Fail closed by construction:** without a provider the refresh probe fails and
  the support actions refuse with `source_changed=True` instead of acting on
  stale state. Every production caller supplies one, so no user-visible behavior
  changes.
- **No new invariant:** the follow-up framework legitimately imports the
  lifecycles whose retained contexts it serves (`incidents`, `config_drift`), so
  a layer rule would be false. The no-import property is enforced by a targeted
  regression test on `followup.py` plus an ownership test for
  `refresh_upgrade_preflight`.
- **Not selected:** the `incidents -> upgrade_preflight` edge (value types and
  the upgrade risk analyzer borrowed for incident findings). It is now the only
  non-presentation incoming edge of the upgrade workflow and is the Stage 9 seam.

### Stage 7 — repository interpretation left the upgrade workflow

`incident_repairs` imported exactly two symbols from `upgrade_preflight`:
`build_repository_health_check` (planning, eligibility re-checks and
post-execution verification) and `apply_repository_health_repairs` (privileged
repair execution). Reading both showed the two are different concerns, and that
`followup`, `incidents` and the preflight itself needed the same two.

| Responsibility inside `upgrade_preflight` | Side effects | New owner |
| --- | --- | --- |
| Pacman/pacman.conf/mirrorlist parsing and repository-health interpretation (`build_repository_health_check`, `parse_pacman_repository_entries`, `count_active_servers`, `resolve_pacman_include_path`, `RepositoryHealthCheck`, `RepositoryMirrorIssue`, `_RepositoryEntry`) | bounded local reads | `core/repository_state.py` (adapter) |
| Privileged mirrorlist restore with run backup and manifest (`apply_repository_health_repairs`, `repository_repair_needs_sudo`, `write_repository_repair_manifest`, `RepositoryRepairResult`, `REPOSITORY_HEALTH_BACKUP_ROOT`) | sudo capture, process execution through the caller's runner, filesystem writes under `/etc` and `/var` | `core/repository_repair.py` (adapter) |
| Revalidate-then-run for a bound executable (`_run_trusted_command`, used 16 times across the workflow) | process execution | `core/trusted_executable.py` as `run_trusted_command`, with the fixed `TRUSTED_SUDO_PATH`/`TRUSTED_PACMAN_PATH` it validates |
| Upgrade planning, handoff, kernel-module aftercare, config drift, security-audit findings, AI advisory, failure diagnosis, CLI | network, process, fs_write | stays in `core/upgrade_preflight.py` |

- **Implemented verbatim:** every moved definition is AST-identical to the code
  it replaces; the only change inside a moved body is the renamed call to the
  shared trusted runner. A direct comparison against the pre-Stage-7 code shows
  identical parse results, identical health-check values across seven scenarios,
  identical repair side effects (target contents, backup directory, runner argv,
  error text) and identical sudo classification.
- **Direction:** `incident_repairs` and `upgrade_preflight` both depend *downward*
  on `repository_state`/`repository_repair`; nothing was reversed. `incidents`
  still imports `incident_repairs` and `upgrade_preflight` still reaches the
  incident workflow through `followup`, which is correct: those are workflow
  invocations, not vocabulary reuse.
- **Layer:** both new modules are adapters. `repository_state` reads files and
  holds no dangerous capability; `repository_repair` owns the privileged write.
  INV-017 was added with that split in mind, and the repository modules are why
  the rule exists.
- **Not moved:** the network boundary (`package_url_status`, AI advisory, failure
  diagnosis), the upgrade handoff, kernel-module aftercare and config drift all
  remain with `upgrade_preflight`. They are workflow behavior, not repository
  interpretation.

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
| `core/incidents.py` (3237) | Stage 5 removed its CLI dispatch and its automation edges and Stage 10 removed its follow-up edges, so what is left is the interactive workflow. Its remaining cycle with `incident_repairs` and `incident_diagnostics` must be designed before another member moves. |
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

1. `{agent, followup}` is the last component left over from the planner cycle and
   the only place where a generic framework and a lifecycle still call each other
   in both directions. Two edges hold it open, and they are different in kind:
   `followup -> agent` is the in-session `/agent` escalation command, which is the
   same misplaced-adapter shape Stage 10 (incidents) and Stage 11 (config drift)
   removed, and `agent -> followup` is the agent running its session through the
   framework. Removing the first through a supplied escalation provider would
   leave the agent dependency one-way and dissolve the cycle, and would be the
   single highest-leverage change left. The same stage should finish the seam
   started here: `build_upgrade_runtime` still hosts the repository and
   kernel-module action adapters inside the framework, so an upgrade
   `runtime_provider` would make `followup` a pure coordinator of supplied
   operations.
2. **Partially done:** Stages 5 and 6 moved the `incidents` CLI runner and the
   shared helper ownership out of subsystem modules. `config_drift`,
   `security_audit` and `upgrade_preflight` still reach their presenter from
   inside their own CLI entry points. That edge is one-way and cycle-free, but
   it means CLI printing still lives in subsystem modules.
3. `core/upgrade_preflight.py` (2607 lines, 6 concern tags — the top hotspot)
   now holds upgrade planning, the handoff, kernel-module aftercare, config
   drift, security-audit findings, AI advisory, failure diagnosis, the follow-up
   refresh operation and its CLI. AI advisory plus failure diagnosis is the
   largest single block left, but it does not participate in the planner cycle:
   it is a size seam, not a cycle seam.
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
