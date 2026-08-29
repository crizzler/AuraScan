# AuraScan Unreleased

- Added blocking default-scan rules for the reported August 2026
  `hyprland-fixes` source, unnecessary privileged `sudo` execution from package
  install hooks, passwordless sudo policy, numeric SUID modes, and correlated
  root remote-access behavior.
- Added the same secret-free remote-access correlation to opt-in deep-static
  source inspection, including bounded non-executable extensionless payloads,
  without treating normal Tailscale use as malicious.
- Extended `security-audit` with bounded `hyprland-fixes` history, installed,
  pending, helper-cache, and exact host-artifact checks. Host evidence is read
  as inert bounded text and does not follow indicator-file symlinks.
- Added defanged regression coverage, presenter metadata/templates, contributor
  guidance, and repository agent/skill instructions for security-rule work.
- Added explicit local AI provider profiles for LM Studio and llama.cpp using
  their loopback OpenAI-compatible APIs, optional local Bearer authentication,
  custom loopback base URLs, and first-run wizard/doctor integration.
- Local AI transport bypasses environment proxies, refuses redirects, bounds
  responses and timeouts, and never falls back to a cloud provider. Added
  keyless, authenticated, URL-validation, wizard, doctor, and
  conservative-failure regression coverage.
- AI responses that violate the required output contract now trigger bounded
  manual review without being mislabeled as confirmed prompt injection, which
  is especially important for smaller local models.
- Added GitHub Actions CI on Python 3.8 and 3.14 for editable installation,
  compile checks, the complete pytest suite, and both strict presenter audits;
  CI explicitly disables live AI access.
