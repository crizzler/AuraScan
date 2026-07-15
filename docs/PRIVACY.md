# AuraScan Privacy Boundaries

AuraScan separates incident collection, optional AI analysis, and privileged
repair so no background process receives both network and repair authority.

## Root Collectors

`aurascan-incident-monitor.service` and
`aurascan-incident-maintenance.service` are offline, read-only collectors. They
do not load user AI configuration, contact a provider, or execute a repair.
They persist bounded redacted reports under `/var/lib/aurascan/incidents/` and
publish only non-sensitive marker/status fields needed by the tray.

## Logged-In AI Assistant

`aurascan-incident-assistant.timer` is disabled until a user explicitly enables
background incident AI. It runs only in that user's systemd session, reads the
user's `0600` AuraScan configuration, and can contact the configured provider.
It receives at most 80 redacted evidence excerpts and 12,000 characters per
request. Incident repair planning may use two requests: triage may select up to
six opaque IDs from AuraScan's locally generated probe catalog, then a final
review may rank only locally verified action IDs. At most 12 bounded read-only
probes run locally. Probe targets and commands are never accepted from provider
output. In `facts-only` mode the provider receives structured findings without
evidence excerpts.

The assistant cannot use `sudo`, invoke privileged repair execution, write
system paths, generate accepted action or probe IDs, or turn AI text into
commands. It may prepare a private broader repair plan for later confirmation;
a matching plan is reusable for up to six hours, but its probes and privileged
preconditions are refreshed before execution. Its reports, retry state, and
notification text are private to the user under
`~/.local/state/aurascan/` with `0700` directories and `0600` files.

## Safe Autopilot

`aurascan-incident-safe-autopilot.service` runs as root without network access
or AI credentials. It obeys the root-owned
`/etc/aurascan/incident-autopilot.conf` policy and defaults to `off`. In `safe`
mode, it accepts only AuraScan's deterministic stale pacman-lock and verified
mirrorlist-restoration recipes. It freshly checks every precondition, creates
private manifests/backups, validates the result, rolls back a failed reversible
action, and enforces a 24-hour cooldown for an identical action ID.

AI output cannot enable this policy, expand its two-recipe allowlist, suppress
a finding, or mark an automatic repair successful. Safe Autopilot remains
independent from AI-guided foreground repair planning.

## Public Marker Data

World-readable incident marker/status files may contain only boot/scan IDs, UID
scope, category severities, resolved categories, coarse repair state, counts,
and timestamps. They must not contain evidence text, commands, paths, package or
application names, provider responses, credentials, or API keys.

## Recovery Environment

AuraScan Recovery is separately enabled and never created as a package-install
side effect. The locally built UKI and release ISO must not contain API keys,
provider configuration, saved NetworkManager profiles, hostnames, usernames,
home paths, incident evidence, or recovery reports. Image validation scans the
complete staged UKI for forbidden credential and user-profile markers before
ESP replacement.

The root-owned `/etc/aurascan/recovery.conf` contains only enablement,
bootloader adapter, refresh policy, opted-in numeric UID, saved-Wi-Fi permission,
image version, and coarse refresh status. It contains no provider key or WLAN
credential.

When saved Wi-Fi use is authorized, AuraScan accepts only regular root-owned
`0600` NetworkManager Wi-Fi profiles from the mounted target. It copies them to
volatile `/run` storage for that recovery session and never copies them into an
image or report. Manually entered WLAN secrets travel through NetworkManager
secret input rather than command arguments and are discarded after connection.

Recovery AI runs only after separate recovery consent and usable network
connectivity. The opted-in user's provider file is accepted only after regular
file, owner, and `0600` checks. A session-only key may be entered when no valid
file exists; it is never written to disk. The two provider requests receive at
most 80 redacted evidence excerpts and 12,000 characters, plus opaque known
probe/action IDs. AI cannot supply executable targets or commands.

Private recovery reports, action manifests, backups, validation output, and
rollback metadata are written under `/var/lib/aurascan/recovery/` with `0700`
directories and `0600` files. Output is bounded and redacted. If the target is
not writable, data remains in recovery RAM unless the user exports it to
removable media.
