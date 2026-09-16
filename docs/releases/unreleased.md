# AuraScan Unreleased

Changes after v0.10.10:

Architecture stabilization stage 14 closeout (documentation only, no behavior change):

- The Stage 14 reassessment re-measured every property of Stages 8–13 from the
  repository: domain leaves, follow-up neutrality and directionality, provider
  supply, presenter rules, adapter direction and the framework invariants all
  still hold, with 19 invariants and zero violations. The campaign is closed and
  `docs/ARCHITECTURE.md` now records the baseline and the triggers that should
  reopen architecture work.
- Corrected stale measurement in the reference documents: the layer table
  reported 91 modules / 72,084 lines / 25 application modules (current:
  92 / 72,340 / 27, now naming the follow-up lifecycle adapters), and
  `docs/SECURITY_BOUNDARIES.md` lists framework neutrality (INV-018/019) among
  the prohibited capability combinations.
- No production code changed; subsequent work is feature- and bug-driven.

Architecture stabilization stage 1 (no behavior change):

- Added `tools/architecture_audit.py`, an offline AST audit that reports module
  responsibilities, coupling, side-effect capabilities, import cycles and
  architecture invariant results, plus `--strict` and `--json` modes.
- Added `docs/ARCHITECTURE.md` and `docs/SECURITY_BOUNDARIES.md`; refreshed the
  README feature taxonomy.
- Added twelve architecture invariants enforced in CI, including "no analyzer
  executes a process", "no `shell=True`", "production stays standard library
  plus declared extras", "no training or research imports", "domain and catalog
  modules stay pure and depend only downward", and "UI entry points contain no
  rule IDs".
- Extracted the trusted-executable identity check from
  `aurascan/core/upgrade_preflight.py` into `aurascan/core/trusted_executable.py`.
  Public API, detection outcomes and the existing test substitution seam are
  unchanged.

Architecture stabilization stage 2 (no behavior change):

- Removed terminal rendering from the core evidence model. `ScanReport` no longer
  defines `render_terminal`; rendering moved to the presentation layer as
  `aurascan.core.scan_report_presenter.render_scan_report`. Rendered output is
  byte-identical, pinned by full golden-text tests.
- `ScanReport.render_terminal` was an undocumented internal method (no exported
  package API, no `__all__`, no documented library interface, CLI-only shipped
  surface), so it was removed outright rather than kept as a compatibility shim.
- This removes the `models` ↔ `presenter` import cycle; `models.py` drops from
  529 to 430 lines and its only remaining internal dependency is `core.risk`.
- Tightened the architecture invariants: catalog modules may depend only on
  domain and catalog, and domain evidence modules may no longer depend on the
  catalog or presentation layers (INV-013, which reproduces the removed defect if
  it returns).

Architecture stabilization stage 3 (no behavior change):

- Removed the last domain-to-service dependency. `AnalysisResult.to_report()` and
  `AnalysisResult.to_dict(package_name, package_version)` assembled a
  `ScanReport` and evaluated risk from inside the evidence model, which held the
  `models` ↔ `risk` import cycle open. Both methods were internal and had no
  callers anywhere, so they were removed rather than relocated.
- `aurascan/core/models.py` is now a leaf module with no intra-package imports;
  no import cycle contains it, and it remains the most depended-on module.
- Corrected the layer taxonomy: `core/risk.py` is a risk-computation module, not
  domain vocabulary. INV-013 was rewritten to the real rule and INV-014 was added
  so the risk layer cannot reach into application, adapter or presentation code.
- Report assembly stays where it already was: the application layer
  (`core/engine.py` builds the `ScanReport` and asks `RiskEngine` for the
  summary).

Architecture stabilization stage 4 (no behavior change):

- Removed terminal rendering from the last six self-rendering report classes:
  `ConfigDriftReport`, `IncidentReport`, `RecoveryReport`,
  `SecurityAuditReport`, `UpgradePreflightReport` and `UpgradeFailureDiagnosis`
  no longer define `render_terminal`. Rendering now lives in
  `config_drift_presenter`, `incident_presenter`, `recovery_presenter`,
  `security_audit_presenter` and `upgrade_preflight_presenter`.
- `preview_diff`, `_check_summary_lines` and `_arch_audit_summary` moved with the
  renderers as display helpers.
- Added the presentation rules: a presenter may not appear in an import cycle
  (INV-015) and a rendering module may not run processes, open the network,
  mutate the filesystem, touch privilege state or call an AI provider (INV-016).
  Presenters are runtime-independent of the objects they render; only the type
  hints are imported, under `if TYPE_CHECKING:`.
- Presenter engines keep display-only copies of three constants that the
  subsystem engines also use, with equality assertions so the wording cannot
  drift.

Architecture stabilization stage 13 (no behavior change):

- Finished the framework ownership cleanup: the upgrade context builder and
  runtime adapter moved out of `core/followup.py` into a new lifecycle-owned
  module, `core/upgrade_followup.py`, together with the upgrade-only probe and
  action identifiers. The generic framework no longer imports `repository_repair`
  or `kernel_module_autopilot`, defines no upgrade vocabulary, and imports only
  `ai_provider`, `hardware_health` and `text_safety`.
- `build_default_runtime` and `run_ask` accept `upgrade_runtime_provider`, and
  `run_agent` forwards it; `cli.py` supplies
  `upgrade_followup.build_upgrade_runtime` for the `ask` and `agent` paths. The
  upgrade workflow now imports its own adapter module instead of reaching into
  the framework.
- Without the provider an upgrade context degrades to facts only: no refresh
  probe, no repository, kernel-module or config-drift action and no execution. A
  second test pins the session hooks and capability providers the runtime
  provider receives.
- The moved functions are AST-identical to their previous definitions; the only
  difference is that the two adapter imports moved from the function body to
  module scope.
- Added INV-019, "lifecycle frameworks must not participate in an import cycle",
  derived from the same component analysis as INV-015 rather than from a name
  list, with the Stage 12 cycle fixture extended to prove it fires. INV-018 was
  not broadened to "or action adapters" because the adapters the framework used
  are shared by the incident repair path too, not upgrade-specific.
- No new cycle: the graph still has exactly the three deliberate components
  (incident planners, intelligence, install-hook/provenance).

Architecture stabilization stage 12 (no behavior change):

- Removed the last planner import cycle. The generic follow-up framework no
  longer imports the agent workflow: the interactive `/agent ACCESS` command is
  now a supplied capability, `agent_escalation_provider`, that the composition
  roots wire in.
- The agent lifecycle owns the whole escalation: `agent.run_agent_escalation`
  resolves the configured access, applies the same validation order and wording
  (configuration error, usage, already guarded, access ceiling) and runs the
  session, returning `AgentEscalationOutcome` so the framework merges a real
  session exactly as before and otherwise does nothing.
- `cli.py` supplies the provider to `ask`, `upgrade` and `config-drift`,
  `incident_cli.py` supplies it to `incidents`, and the agent supplies it to the
  guarded follow-up session it hosts itself. The upgrade, config-drift and
  incident workflows forward the capability to every interactive session site
  and never import the agent module.
- Without a provider the session reports that Repair Agent escalation is
  unavailable, generates no command and starts nothing; a provider that reports
  no session leaves the framework state untouched. Both paths, the agent-owned
  refusal wording, the forward-only wiring and a real workflow session are
  covered by tests.
- Added INV-018, "lifecycle frameworks must not import concrete lifecycle
  workflows", with the framework and lifecycle-workflow roles recorded in the
  audit tool and negative fixtures for a framework importing the agent workflow
  and any other concrete workflow.
- No planner cycle is left: `agent`, `followup`, `config_drift`,
  `upgrade_preflight` and `incident_repairs` are all cycle-free. The remaining
  components are the incident planners, the intelligence snapshot transaction
  and the install-hook/provenance group.

Architecture stabilization stage 11 (no behavior change):

- Moved the config-drift follow-up adapters out of the generic framework and back
  into the lifecycle that owns drift policy: `context_from_config_drift` and
  `build_config_drift_runtime` now live in `core/config_drift.py`, and
  `followup` no longer imports `config_drift` or its presenter at all. The two
  moved functions are AST-identical to the originals apart from their import
  statements and the `FollowUpContext`/`FollowUpRuntime` annotations, which
  became strings: Python 3.8 evaluates annotations when the `def` runs, so an
  unquoted lazily imported name is a `NameError` there even though CPython 3.14
  defers annotations. A static architecture test now fails on any production
  annotation a module has not bound, and is itself exercised against a fixture.
- The one piece of drift behavior the framework still hosted — re-deriving the
  fix an upgrade session may apply and deciding whether it can be a safe default
  — became `config_drift.prepare_config_drift_remediation`, which returns a
  prepared `ConfigDriftRemediation` and applies it by running the existing
  guarded assistant command unchanged.
- The framework now receives those operations from its callers:
  `build_default_runtime`, `run_ask`, `run_agent` and `build_upgrade_runtime`
  accept `config_drift_runtime_provider` / `config_drift_remediation_provider`;
  the CLI supplies both and the upgrade preflight supplies the remediation
  provider at its three runtime sites.
- Without the runtime provider a config-drift context degrades to facts only, and
  without the remediation provider the upgrade session drops the drift action
  instead of applying state it cannot re-verify. Both fail-closed paths and the
  prepared-fix path are covered by tests.
- `core/config_drift.py` left the planner component: the strongly connected
  component dropped from three members to two and the remaining cycle is
  `{agent, followup}`. `core/followup.py` is now 2066 lines with three concern
  tags and has left the advisory size budget.

Architecture stabilization stage 10 (no behavior change):

- Moved the incident-family follow-up adapters out of the generic framework into
  `core/incident_followup.py`: loading a retained incident result
  (`context_from_saved_incident`, `context_from_latest_saved_incident`) and
  building the incident/maintenance runtimes (probe handling, verified repair
  application, marker acknowledgement). `followup` no longer imports the
  incident workflow, its diagnostics planner, its repair planner or its
  automation layer.
- The framework now receives those operations from its callers:
  `run_ask`, `build_default_runtime` and the agent accept
  `incident_context_provider` / `incident_runtime_provider`; the CLI supplies
  them for retained results and the incident CLI supplies the runtime provider
  for live sessions.
- Without a provider the framework builds no incident runtime, so no probe or
  repair runs from stale state; the incident workflow simply offers no session.
  Both fail-closed paths are covered by tests.
- The planner component drops from six modules to three
  (`agent`, `config_drift`, `followup`); the incident workflow, diagnostics and
  automation now form their own component.

Architecture stabilization stage 9 (no behavior change):

- Extracted the inert upgrade values into a new domain module,
  `core/upgrade_models.py`: `UpgradePackage`, `ForeignPackageInfo`,
  `UpgradePlan` and `SystemSnapshot` (fields, `to_dict` projections and the
  `available`/`package_names` helpers). The module imports nothing at runtime
  and performs no I/O.
- Collecting a snapshot reads the machine, so it stayed in the workflow as
  `upgrade_preflight.collect_system_snapshot`; only the value is shared.
- Incident collection now builds its snapshot and kernel-module check input
  from the shared values, so `core/incidents.py` no longer imports
  `core.upgrade_preflight` at all.
- `core/upgrade_preflight.py` left the planner component: the strongly
  connected component dropped from seven members to six. `UpgradeFinding`,
  `UpgradeOptions`, `UpgradeConfig` and `UpgradeFailureDiagnosis` stayed with
  the workflow that decides them.

Architecture stabilization stage 8 (no behavior change):

- The upgrade lifecycle now owns its own follow-up refresh operation:
  `core.upgrade_preflight.refresh_upgrade_preflight` replaces the private helper
  that `core/followup.py` used to build by importing `run_upgrade_preflight`.
- `build_upgrade_runtime`, `build_default_runtime`, `run_ask` and `run_agent`
  accept the provider (`refresh_report` / `refresh_upgrade_report`) and `cli.py`
  supplies it, so the follow-up framework no longer imports the upgrade workflow
  and the two no longer call each other in both directions.
- Without a provider the refresh probe fails and the support actions refuse
  instead of acting on stale state; every production caller supplies one, so no
  user-visible behavior changes.
- The planner component is still seven modules: the remaining route between the
  two subsystems is `followup -> incidents -> upgrade_preflight`.

Architecture stabilization stage 7 (no behavior change):

- Extracted repository interpretation from `core/upgrade_preflight.py` into
  `core/repository_state.py`: pacman.conf and mirrorlist parsing, the repository
  health/issue values and the `build_repository_health_check` state builder. It
  performs bounded local reads only — no process, network, privilege or write.
- Extracted the privileged mirrorlist restore into `core/repository_repair.py`:
  run backup, install, ownership preservation and the repair manifest, with sudo
  captured through the trusted-executable boundary.
- Moved the revalidate-then-run helper to `core/trusted_executable.py` as
  `run_trusted_command`, together with the fixed `sudo`/`pacman` paths it
  validates, so every caller revalidates through one module.
- `core/incident_repairs.py` no longer imports `core.upgrade_preflight` at all:
  repair planning reads repository state and executes the repair through the new
  adapters. The planner component dropped from eight modules to seven and no
  longer contains the repair planner. All moved code is byte-for-byte the same
  logic; only the internal runner call was renamed.
- Added INV-017 («platform adapters must not depend on application workflows»),
  which encodes why the edge existed and prevents it returning.

Architecture stabilization stage 6 (no behavior change):

- Moved the incident value types out of the incident workflow into a new domain
  module, `core/incident_models.py`: the report, evidence, finding, coredump,
  diagnostic and repair value types, the incident state paths, the schema and
  report identifiers, and the boot-target predicate. Repairs, diagnostics,
  automation, the presenter and recovery now import their data types from the
  vocabulary module instead of the workflow.
- Moved the shared helpers into dedicated owners: privacy redaction into
  `core/redaction.py` (domain) and both the atomic private-state write and the
  bounded command capture into adapters `core/state_file.py` and
  `core/bounded_process.py`.
- `core/incident_repairs.py` no longer imports the incident workflow at all. The
  extracted code is byte-for-byte the same logic, including the timeout retry,
  the 127 error path and every redaction pattern.
- The planner component is still eight modules: the remaining route between the
  repair planner and the workflow is now
  `incident_repairs -> upgrade_preflight -> followup -> incidents`, which names
  the next seam.

Architecture stabilization stage 5 (no behavior change):

- Moved incident command-line dispatch out of the incident workflow. The nine
  automation-control flags (`--set-auto-repair-policy`, `--safe-autopilot-enabled`,
  `--apply-request`, `--enable-background-ai`, `--disable-background-ai`,
  `--auto-repair`, `--background-ai-status`, `--capture-safe-autopilot`,
  `--background-assist`) are now handled by `core/incident_cli.py`, a
  presentation-layer entry point, which delegates the incident workflow itself
  to `core.incidents.run_incidents`.
- The incident workflow no longer imports the automation or repair-execution
  modules to service its own flags, removing 8 of its 9 edges into
  `incident_automation`. Root-privilege refusals, exit codes, messages, the
  privileged request-file validation and the JSON helper output are unchanged.
- The planner component remains eight modules: breaking dispatch did not split
  it, because `followup`, `incidents` and `incident_automation` still call each
  other's planners. `core.incident_cli` is registered as a UI entry point, so
  INV-007 now prevents application code from importing it back.

See [v0.10.10](v0.10.10.md) for signed runtime-intelligence support, detection-data
tray controls, the optional-install-script wording, and the recovery-bearing
release validation record. Production feed and signing keys remain
unconfigured; provisioning them requires a separately reviewed application
release. No automatic update is enabled by package installation.
