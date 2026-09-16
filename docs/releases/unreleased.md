# AuraScan Unreleased

Changes after v0.10.10:

Consent-gated review adjudication capture and export (opt-in research plumbing):

- Review acceptances now also capture a local, append-only record that binds the
  operator's judgment to the exact PKGBUILD, install-hook and source-metadata
  hashes, the scan fingerprint, the finding identities and the scanner, rule and
  intelligence provenance. Capture is best effort: it can never block a scan, a
  review acceptance or a build.
- The judgment is an allowlisted label supplied with
  `--aurascan-adjudication` (`benign_false_positive`, `benign_expected_behavior`,
  `suspicious_unconfirmed`, `confirmed_malicious`). Without a label the record
  stays unlabeled, which is not a training target, and an unrecognized label is
  rejected instead of being silently dropped. Free-text review reasons are never
  copied into the record, and a revocation or relabel supersedes the earlier
  judgment while the original stays in the log.
- `aurascan evidence status` reports capture counts, labels and consent state;
  `aurascan evidence consent --purpose P --confirm P` records consent for one
  named purpose (`analysis`, `training`, `commercial_training`,
  `redistribution`), and consent for one purpose never authorizes another;
  `aurascan evidence export --purpose P --out FILE` writes quarantine candidates
  and refuses without that consent or without labeled records.
- Exported candidates are never admitted: they carry `partition: quarantine`,
  `admission: not_admitted`, unresolved rights for every purpose, a
  hash-only content binding and a derivation-family token. Raw package bytes,
  host paths, operator identity and free-text notes are excluded, so binding
  real content stays a separate offline intake step under its own consent and
  admission review. Nothing on this path can admit data, grant rights, choose a
  split, contact a network, or train a model, and AI credentials are not read.

Build-time privilege elevation is now blocked and cached sudo is cleared:

- `PRIV-BUILD-PRIVILEGE-ELEVATION-001` is a CRITICAL blocker for `sudo`, `doas`,
  `pkexec`, `su` and `run0` in package build logic, and for the non-`sudo` family
  in install hooks. `sudo` in an install hook keeps its existing
  `EXEC-INSTALL-HOOK-SUDO-001` rule, and only `sudo -u <non-root user>` keeps the
  narrow justification. A build step that tries to escalate never reaches
  makepkg, so a cached sudo timestamp cannot be used by it.
- Immediately before the makepkg handoff the packaged entry point now clears the
  operator's cached sudo timestamp with the trusted absolute `sudo -k`. The step
  reports rather than blocks, because a user who may not run sudo has no cached
  timestamp to remove; the JSON envelope carries `sudo_cache_invalidation`
  (`not_requested`, `absent`, `invalidated`, `unconfirmed`, `untrusted`) and an
  unconfirmed step adds a warning instead of failing the build.
- The hygiene step is requested only by the real entry point. `run()` defaults to
  a no-op seam, so an in-process or test caller can never clear a developer's
  credentials as a side effect.

Declared derived packages now get honest coverage instead of silence:

- A vendor advisory record may declare reviewed `derived_packages` (for example
  `ungoogled-chromium` or `librewolf`). When one is installed,
  `SEC-VENDOR-ADVISORY-DERIVED-PACKAGE-UNMAPPED` reports MEDIUM that the upstream
  floor cannot be evaluated for it.
- No version comparison is performed and the finding never claims exposure,
  because a derivative can follow, lag or backport fixes independently. Its
  recommended action is to check the derivative's own advisory. Undeclared
  lookalike names still produce nothing, and a pending update of that exact
  package suppresses the note from the upgrade summary while the installed-state
  audit keeps it.

AUR account/SSH backdoor detection (new rules):

- `PRIV-ACCOUNT-BACKDOOR-001` is a CRITICAL blocking correlation: the same
  package-controlled text sets an account password to a literal value, grants
  that account privilege, and exposes SSH. It catches a remote root-equivalent
  login assembled from ordinary account, sudo and SSH facilities, with no
  downloader, obfuscation or embedded payload to detect.
- `PRIV-ACCOUNT-CREDENTIAL-001` reports the literal-credential behavior alone as
  HIGH needing review, `PRIV-SUDO-ADMIN-GROUP-001` reports an
  administrative-group sudo policy that does not use `NOPASSWD`, and
  `DEEPSTATIC-PRIV-ACCOUNT-BACKDOOR-001` covers the same chain in acquired
  source.
- The credential half is read only from shell command position: piped
  `chpasswd`, an explicit password flag, and a `chpasswd` heredoc body count,
  while a generated password, a shell variable and quoted documentation do not.
  Ordinary locked service accounts (`useradd --system`, no interactive password,
  no administrative group, no SSH exposure) stay negative cases, so daemons are
  not flagged merely for owning a user.
- Evidence labels are fixed strings, so the observed account name, password,
  hash and policy line never appear in a report. The motivating incident is the
  2026-09-14 aur-general report about the removed package `x11-qemu-validation`;
  the account name and password circulated by third-party summaries were not
  established from the primary source and are not encoded anywhere.

Vendor security floors are multi-product and exploitation-aware (intelligence 2.0):

- Vendor advisories now record the vendor's own severity and an explicit
  exploitation state, and the comparator is declared per entry
  (`chromium_four_part`, or the new `numeric_dotted_upstream` for
  two-to-four-component vendor releases). Vendor severity maps to finding
  severity in the application; a feed still cannot select a rule or policy.
- `SEC-VENDOR-SECURITY-FLOOR-LAG` is the new HIGH rule for a verified vendor
  floor whose exploitation is not established. `SEC-KNOWN-EXPLOITED-VERSION-LAG`
  keeps the exploited case, so critical vulnerability exposure is no longer
  presented as known exploitation.
- Added `chromium` below `153.0.8010.47` (Critical CVE-2026-91749), `firefox`
  below `156.0` (MFSA 2026-90) and `thunderbird` below `156.0` (MFSA 2026-94),
  reviewed on 2026-09-16 with no exploitation evidence. A build between the two
  Chromium floors is clean for the known-exploited entry and still below the
  later one; a release at or above every captured floor matches nothing.
- Floors map to exact Arch package names, so browser forks (LibreWolf, Zen
  Browser, Floorp) are never matched by version similarity. Unsupported version
  shapes keep unresolved coverage, now with a single warning per package instead
  of one per advisory.
- The runtime intelligence wire contract moves to schema and engine capability
  `2.0`, because the exploitation state, vendor severity and comparator set are
  part of the reviewed format. A `1.0` payload, manifest or stored generation is
  rejected rather than reinterpreted: refresh against a `2.0` bundle, and the
  bundled `2.0` baseline stays available meanwhile. A `1.0` detection is never
  carried over silently. The general-purpose security-audit report schema is
  unchanged at `1.0`; only the intelligence contract changed.
- No detection, blocking behavior, AI authority, or network/privilege surface is
  otherwise changed, and no browser, package payload, or live feed is contacted
  to evaluate a captured floor.

Deep-static Git object signature evidence (observational):

- Explicit `--deep-static` acquisition now reports the signature state of the
  exact Git object it resolved: the local object type (annotated tag,
  lightweight tag or commit), whether a signature is present, its format, a
  verified signer fingerprint, and whether that fingerprint matches a declared
  `validpgpkeys` entry. The previous finding text that said signed tag
  verification was not implemented is replaced.
- Validity is decided by Git's own `verify-tag`/`verify-commit` with the trusted
  absolute Git and GnuPG files, a private temporary GnuPG home, locally
  available key material and a bounded deadline. Only machine-readable
  `VALIDSIG` status can establish a signer fingerprint, and an older Git without
  machine status leaves the fingerprint unavailable rather than guessing one.
- Declared correlation is reported separately from cryptographic validity. A
  matching `validpgpkeys` fingerprint is recorded as
  `matched_declared_validpgpkey`; an undeclared signer is never trusted, an
  invalid signature is reported distinctly without blocking, and expired or
  revoked signing-key status is never presented as an ordinary valid declared
  signer. Unsupported formats (SSH/X.509), missing keys and unavailable
  verifiers stay explicit unresolved coverage instead of "unsigned".
- Signature evidence is observational: it never changes acquisition status,
  blocking policy, rule IDs, AI authority or the network/privilege surface, and
  it never establishes signer authorization, official origin, source safety,
  review or an uncompromised upstream. Verification performs no implicit key
  retrieval, so it works offline when key material is already available.

Upgrade advisory evidence (product fix):

- `aurascan upgrade` now evaluates installed-version advisories from captured
  local package evidence instead of a placeholder value. The snapshot captures
  `pacman -Q` name/version pairs through the same resolved trusted pacman
  identity as its other queries, within a bounded query size and record count.
- An installed package below a verified advisory floor now raises the existing
  HIGH `SEC-KNOWN-EXPLOITED-VERSION-LAG` finding and can require the normal
  high-risk confirmation, where the earlier placeholder evidence could only
  produce MEDIUM unresolved coverage. An exact mapped repository candidate that
  reaches the floor still suppresses the warning.
- Missing, invalid, conflicting, oversized or unqueryable version evidence keeps
  the existing `SEC-VENDOR-ADVISORY-VERSION-UNRESOLVED` unresolved-coverage
  outcome for that installed name. Unknown evidence is never read as absence,
  and no fabricated version string is used. Rule IDs, severities, blocking
  semantics, AI authority and the network/privilege surface are unchanged.
- Installed versions are what the local pacman database reports. They do not
  authenticate package origin, repository integrity, or downstream backport
  equivalence.

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
