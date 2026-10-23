# AuraScan Unreleased

Changes after v0.10.12:

- The interactive AUR continuation now labels its choices as
  `[s/r/n] (default: s)` and shows the manual `aurascan-makepkg` example only
  when the AUR update is left pending. Enter, `s`, and `S` all select the
  sandbox; `r`/`R` selects repository-only, and `n`/`N` keeps the upgrade
  blocked.
