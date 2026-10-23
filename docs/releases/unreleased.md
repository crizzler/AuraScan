# AuraScan Unreleased

Changes after v0.10.11:

- Interactive `aurascan upgrade` now offers the isolated devtools AUR build as
  the default continuation when the backend is available, instead of requiring
  `AURASCAN_AUR_SANDBOX=devtools` or `--aur-sandbox devtools` up front.
  Repository-only and keep-blocked choices remain, and `--yes`, `--json`, dry
  runs, and runs without an interactive answer keep the original hard stop.
- Pacman-hook scans bind cached archives to the root-owned sync databases by
  filename and SHA-256. Verified official repository archives use a fast
  deterministic install-hook scan; routine systemd service management is
  LOW/non-manual and auxiliary ClamAV/AI is skipped. Local, AUR, unknown, or
  checksum-mismatched archives keep the full scan and blocking behavior. The
  hook now prints one compact transaction summary and lists blocked packages
  with their rule IDs.
