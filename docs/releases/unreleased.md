# AuraScan Unreleased

Changes after v0.12.2:

- Add `aurascan npm-audit [PATH]`, an offline pre-install review of a
  JavaScript project. It reads `package.json` and the project files named by
  the `preinstall`, `install`, `postinstall`, and `prepare` commands as
  inert text, with no npm, node, shell, or registry invocation, and reports one
  CRITICAL blocking finding when a single file reads the environment, contacts
  a network destination, and evaluates dynamic code, and one HIGH blocking
  finding when a lifecycle command pipes a download into a shell or
  interpreter. Files it cannot inspect stay a manual-review coverage finding,
  and a clean result never means safe to install. Optional `aurascan-desktop`
  wiring for this command is not included yet.

- The optional `aurascan-desktop` package is prepared in `packaging/desktop/`
  but is not published; see its README for the publication gate.

- Add `aurascan settings`, a read-only `aurascan-settings/1` projection of the
  invoking user configuration with AI credentials reduced to presence
  booleans, plus `aurascan settings set-ai-key`, which stores one provider
  credential read from stdin at mode `0600` and never echoes it. Storing a
  credential does not enable AI.
- Add `aurascan instruction-audit --expect-report-id` and `--expect-sha256`
  for `--approve` and `--disable`, so a client can prove it acted on the report
  and content it displayed. The flags are refused without an action or with a
  malformed digest.
- Add `docs/DESKTOP_CONTROL_CENTER.md`, the authority model and phased plan for
  desktop control of AuraScan.
