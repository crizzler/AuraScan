# AuraScan Unreleased

Changes after v0.10.11:

- Interactive `aurascan upgrade` now offers the isolated devtools AUR build as
  the default continuation when the backend is available, instead of requiring
  `AURASCAN_AUR_SANDBOX=devtools` or `--aur-sandbox devtools` up front.
  Repository-only and keep-blocked choices remain, and `--yes`, `--json`, dry
  runs, and runs without an interactive answer keep the original hard stop.
