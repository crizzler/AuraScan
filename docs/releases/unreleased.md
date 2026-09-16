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

See [v0.10.10](v0.10.10.md) for signed runtime-intelligence support, detection-data
tray controls, the optional-install-script wording, and the recovery-bearing
release validation record. Production feed and signing keys remain
unconfigured; provisioning them requires a separately reviewed application
release. No automatic update is enabled by package installation.
