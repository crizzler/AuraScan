# AuraScan Unreleased

Changes after v0.10.10:

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
