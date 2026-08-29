# AuraScan Privacy Boundaries

AuraScan separates offline collection, optional AI analysis, and privileged
repair so no background process receives both network and repair authority.

## Root Collectors

`aurascan-incident-monitor.service` and
`aurascan-incident-maintenance.service` are offline, read-only collectors. They
do not load user AI configuration, contact a provider, or execute a repair.
They persist bounded redacted reports under `/var/lib/aurascan/incidents/` and
publish only non-sensitive marker/status fields needed by the tray.

## Agent Instruction Guard

Agent Instruction Guard is an opt-in, unprivileged scanner for recognized
AI-agent control files under a user's home directory. Its offline monitor runs
after login and every five minutes with network access disabled, a read-only
home, private writable state, low CPU/I/O priority, and all supported AI
credentials removed from its environment. It reads files only as bounded inert
text and never imports, renders, sources, or executes them.

The default `agent-surfaces` mode discovers `AGENTS.md`,
`AGENTS.override.md`, `SKILL.md`, `CLAUDE.md`, `CLAUDE.local.md`, and Claude
rules, commands, agents, skills, memory, settings, hooks, MCP/plugin manifests,
and text resources associated with discovered skills. Optional `all-markdown`
mode applies content rules to other Markdown files but does not baseline their
integrity. Explicit imports and file symlinks are followed only to regular files
inside an allowed root; symlinked directories are not traversed. Cache, trash,
VCS, dependency, and virtual-environment trees are pruned, and each scan is
bounded by traversal, candidate, file-size, and elapsed-time limits.

Private reports, manifests, AI jobs, alert records, and disable receipts are
stored under `$XDG_STATE_HOME/aurascan/instruction-guard/` (normally
`~/.local/state/aurascan/instruction-guard/`) with `0700` directories and
`0600` files. They may contain normalized file identity and metadata, hashes,
rule IDs, bounded redacted evidence, integrity status, approval bindings, and
action history. Treat this as private security data. Approvals are bound to the
content hash and a hash of machine identity plus UID; restoring state onto a
rebuilt machine does not establish trust. Corrupt, symlinked, wrongly owned, or
permission-weakened state is rejected rather than overwritten.
AuraScan retains the current Instruction Guard report and at most the newest 32
reports within a 256 MiB aggregate history budget. It retains at most 2,048
generic alert envelopes, including at most 256 acknowledged envelopes when
capacity permits. This pruning limits storage growth; it does not approve files
or erase the manifest's persistent integrity state.

Desktop notifications and tray/public status contain only a generic severity,
count, and request to review. They never contain paths, snippets, usernames,
credentials, provider output, or other file content. Acknowledging an alert
deduplicates the same notification; it does not approve a file.

Instruction Guard AI is a second, independent opt-in. Its user timer processes
at most one queued job per run through the already configured local or cloud
provider. A request contains at most 12 KiB of redacted suspicious evidence and
asks for strict JSON without tools. The provider may return a bounded verdict,
severity, confidence, matched behavior families, and reasons. AI output is
labeled interpretation, cannot lower deterministic severity, cannot trust an
integrity change, and cannot provide commands. Disabling Instruction Guard AI
causes zero provider calls. The offline monitor never loads provider
credentials.

Confirmed disable is not quarantine. AuraScan may atomically rename only an
unchanged, user-owned, standalone regular instruction file after confirmation
and writes a private receipt for exact restoration. Settings, hooks, plugin
manifests, scripts, shared configuration, and symlinks are manual-only. Restore
requires unchanged disabled content, a missing original path, and a safe parent
directory, then returns the file to unreviewed status rather than trusting it.

This monitor does not preflight pasted commands or download links, intercept
file opens or processes with fanotify, or continuously prevent access between
scans. Same-UID malware can read or alter user files and attack AuraScan's user
state; root malware can disable or deceive the monitor. These limits remain
true even when state permissions and service sandboxing are correct.

## Package Security Intelligence

`aurascan security-audit` uses a packaged, SHA-256-validated snapshot of known
AUR campaign package names. `--refresh` requests only the manifest's HTTPS
plain-text list, caps it at 2 MiB and 20,000 valid names, rejects shell syntax,
and stores the validated response under
`~/.local/state/aurascan/security-intel/` with `0700`/`0600` permissions.
AuraScan never executes the upstream incident script.

The local audit reads installed package names/versions, at most the newest 4 MiB
from each supported pacman history log, and only direct package-directory names
from bounded AUR helper caches. It does not upload these facts to AI. Its JSON
report contains matching package names and bounded matching history records, so
users should treat that report as private system-security data.

When installed, `arch-audit` contacts the Arch Security Tracker according to its
own network behavior and returns official advisory JSON to AuraScan. `--offline`
skips that request. Campaign and advisory findings remain separate, and neither
source authorizes automatic package removal or host cleanup.

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

## Local AI Providers

The `lmstudio` and `llamacpp` providers send the same bounded AI request to an
OpenAI-compatible server on loopback instead of a cloud API. Their defaults are
`http://127.0.0.1:1234/v1` and `http://127.0.0.1:8080/v1`. They remain disabled
until `AURASCAN_AI_ENABLED=1`; choosing a local provider does not silently opt
the user into AI analysis.

AuraScan accepts only loopback HTTP(S) overrides in `AURASCAN_AI_BASE_URL`,
bypasses environment proxies, refuses redirects, and never falls back to a
cloud provider. A server without authentication needs no dummy credential. If
the server requires authentication, its optional Bearer token is read from
`AURASCAN_LOCAL_AI_API_KEY`, kept in the permission-checked provider config, and
excluded from reports and diagnostics.

This boundary keeps AuraScan's request on the same host; it cannot guarantee
what a separately managed inference server, model, extension, or server log
does with that request. AuraScan does not start or configure the server, load or
download models, enable tools or MCP, or grant the model additional filesystem
or command access. `aurascan doctor` makes no request unless the user supplies
`--check-ai`.

## Foreground Contextual Follow-Up

Interactive upgrade, incident, maintenance, and config-drift workflows may open
the contextual assistant when the configured AI provider is enabled. A session allows
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
probe/action IDs. AI cannot supply executable targets or commands. For a local
provider, `127.0.0.1` refers to the recovery environment rather than the
installed system. Recovery does not start or forward LM Studio or
`llama-server`; if the endpoint is absent, deterministic recovery remains
available and AuraScan does not substitute a cloud provider.

Private recovery reports, action manifests, backups, validation output, and
rollback metadata are written under `/var/lib/aurascan/recovery/` with `0700`
directories and `0600` files. Output is bounded and redacted. If the target is
not writable, data remains in recovery RAM unless the user exports it to
removable media.
