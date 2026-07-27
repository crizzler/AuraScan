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

## Foreground Contextual Follow-Up

Interactive upgrade, incident, maintenance, and config-drift workflows may open
the contextual assistant when ordinary network AI is enabled. A session allows
at most eight questions and twelve provider requests. Each request contains no
more than 12,000 characters assembled from a bounded redacted source result,
the current redacted question, and a trimmed in-memory conversation.

AuraScan accepts only known fact, probe, and verified action IDs from strict AI
JSON. Provider-supplied commands, scripts, paths, package targets, service
names, file edits, and unknown IDs are discarded. A requested action is rebuilt
from current local state, previewed, and confirmed separately. Parent `--yes`
options do not authorize follow-up actions.

Redacted source contexts are stored under
`~/.local/state/aurascan/follow-up/` in a `0700` directory with `0600` files.
They are fingerprinted, retained for at most 30 days or 50 records, and rejected
if their content or permissions change unexpectedly. Follow-up questions,
answers, provider payloads, keys, and local command output are never persisted
there.

Config contents and diffs remain excluded unless the originating config-drift
run explicitly allowed redacted AI diff sharing. JSON, `--yes`, `--no-ai`,
non-interactive, pacman-hook, root-collector, background-service, and recovery
runtime paths do not open contextual chat.

Hardware-related questions can trigger a foreground read-only hardware probe
before the first provider request. Its normalized facts may contain CPU, GPU,
RAM capacity and DIMM topology, mainboard and BIOS model/version, driver and
microcode versions, temperatures, fan states, memory pressure, repository
version comparisons, `fwupd` update availability, and category counts for
current-boot hardware errors. The existing AI consent and redacted/facts-only
policy applies to these facts.

AuraScan does not read or transmit system serial numbers, board serial numbers,
UUIDs, asset tags, raw firmware tables, or raw SPD/I2C memory data. Exact RAM
timings are marked unavailable when SMBIOS does not expose them. Hardware
package and firmware checks are read-only; they do not synchronize pacman's
active databases, flash firmware, or install drivers. Offline boot and weekly
collectors gather only static `/proc` and `/sys` inventory and do not run these
foreground commands or contact a network.

## Foreground Full-Control Repair Agent

The Repair Agent is disabled beyond `guarded` tools unless the user configures
`user-shell` or `root-shell`. It runs only in an interactive foreground
terminal. Root collectors, background services, pacman hooks, JSON workflows,
and the recovery environment cannot invoke it.

The model receives the retained redacted AuraScan context, the current
redacted question, a bounded in-memory conversation, and bounded terminal
results. Terminal output is redacted by default. Sending bounded raw output
requires typing `SHARE FULL TERMINAL OUTPUT` for that session. The model sees
at most 32 KiB per command and 128 KiB per session, within a 12,000-character
request. API keys and other AuraScan secrets are omitted from the executor's
minimal environment.

`user-shell` commands run as the logged-in user. `root-shell` requires a
root-owned policy opt-in plus the exact phrase
`GRANT AI FULL ROOT CONTROL` for every session. The provider and unprivileged
assistant keep the API credential; the root broker receives no provider
configuration. Root capabilities are stored under `/run/aurascan-agent/`,
expire quickly, and are bound to the UID, originating process/start time,
terminal, retained-context fingerprint, and approval ceiling.

Before root execution, AuraScan creates a validated Btrfs/Snapper snapshot when
supported. Continuing without one requires typing
`CONTINUE WITHOUT ROLLBACK`. Snapshots cannot protect other disks, firmware,
credentials, networking, remote services, or every local configuration.

User audit records are stored under `~/.local/state/aurascan/agent/`; root
manifests are stored under `/var/lib/aurascan/agent/`. Directories use `0700`
and files use `0600`. They contain command hashes, redacted command renderings,
approval metadata, exit status, snapshot state, and bounded redacted output.
They do not intentionally retain API keys, questions, or AI answers and are
limited to 30 days or 50 sessions.

Unrestricted root mode is user-authorized remote code execution. After a root
command starts, it can alter AuraScan, read credentials, disable auditing,
escape best-effort process controls, or send data over the network. No
in-process policy can guarantee privacy or containment against authority that
broad. The typed grants and audits prevent accidental activation; they do not
make unrestricted root execution safe.
Unrestricted root commands can defeat these software boundaries.

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
