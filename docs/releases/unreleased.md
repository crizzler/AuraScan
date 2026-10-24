# AuraScan Unreleased

Changes after v0.11.1:

- Add `aurascan settings`, a read-only `aurascan-settings/1` projection of the
  invoking user's configuration with AI credentials reduced to presence
  booleans, plus `aurascan settings set-ai-key`, which stores one provider
  credential read from stdin at mode `0600` and never echoes it. Storing a
  credential does not enable AI.
- Add `docs/DESKTOP_CONTROL_CENTER.md`, the authority model and phased plan for
  desktop control of AuraScan. The optional `aurascan-desktop` package is
  prepared in `packaging/desktop/` but is not published; see its README for the
  publication gate.
