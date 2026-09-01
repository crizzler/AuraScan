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
deduplicates the same notification; it does not approve a file. AuraScan calls
desktop notification only through a captured and revalidated
`/usr/bin/notify-send`; if it is unavailable, private CLI/tray state remains
available without spawning another executable from `PATH`.

Instruction Guard AI is a second, independent opt-in. Its user timer processes
at most one queued job per run through the already configured local or cloud
provider. A request contains at most 12 KiB of opaque evidence IDs, fixed
deterministic reasons, semantic behavior labels, and deterministic line
locations; it contains no path or source snippet and asks for strict JSON
without tools. AI rationale must map to supplied evidence IDs. It cannot invent
or change a line, lower deterministic severity, trust an integrity change,
claim execution or compromise, or provide commands. Disabling Instruction
Guard AI causes zero provider calls. The offline monitor never loads provider
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

## Local Package Scan State

Package scan cache and history are stored locally under
`~/.cache/aurascan/` by default. Makepkg review decisions default to
`~/.local/share/aurascan/review_decisions.db`. These stores can contain package
metadata, finding records, local control-file or observed-artifact paths, file
hashes, review decisions, and the opaque digest/status of the bounded
package-checkout snapshot. The repository-provenance pass does not persist
artifact bytes or matched command text in that manifest. Treat these databases
as private local security data; same-UID malware can read or alter user-owned
cache or data state, and root malware can defeat the scanner.

## Package and Advisory AI Boundaries

Optional package AI receives only a bounded head/tail selection of numbered
text lines represented as JSON data. It has no tools, filesystem authority, or
URL/command channel. AuraScan accepts only a strict raise-only schema with
allowlisted behavior labels and references to lines actually supplied. A
no-additional-concern response cannot suppress deterministic findings or mark a
package clean, safe, trusted, or approved.

Upgrade AI receives a bounded redacted transaction summary. It may only raise,
up to HIGH, the severity of a rule ID already present in deterministic
findings. It cannot create a standalone finding or action, change blocking
policy, lower a finding, or authorize an AUR build or package-manager handoff.

Config-drift, incident, and recovery AI use similarly bounded exact schemas.
Only known local evidence, probe, and verified action IDs survive validation.
Model prose remains untrusted interpretation. AuraScan normalizes it and rejects
recognized scheme, bare, IP, email, and obfuscated network destinations;
direct or indirect action requests; sentence-leading imperative verbs; named or
generic package-manager/install-helper advice; nominalized operation or
invocation advice; credential-copy/share wording; questions; commands; terminal
controls; forged AuraScan labels; credential-like assignments; and unsupported
safe/compromised claims. Duplicate keys, extra fields, excessive lists/strings,
malformed JSON, and provider errors also produce a fixed, secret-free failure
explanation. A rejected raw response is not persisted or rendered; accepted
bounded interpretation may appear in the private report or terminal view.

These checks reduce recognized prompt-injection and social-engineering forms;
they cannot prove arbitrary natural language harmless. Model prose has no
tools, URL fetching, command execution, or policy authority. Only known IDs
from AuraScan's local deterministic state can survive schema validation, and
each separately guarded action keeps its existing confirmation and policy
boundary.

Default cloud and local provider transports refuse redirects. Gemini
credentials are sent in a request header rather than a URL. Source-acquisition
reports separately omit URL userinfo, query strings, and fragments so embedded
credentials or tokens are not retained in scan state.

## Explicit Source Acquisition and Native Tools

Default scanning performs no source/key network request. Explicit deep-static
acquisition may contact declared source hosts and a configured keyserver. It
rejects URL userinfo, localhost, and non-public IP literals before the initial
request and after redirects, but this lexical policy does not eliminate DNS
rebinding. Git checkout can also consume disk before the acquired tree is fully
analyzed. Use a disposable, resource-limited environment for adversarial
acquisition and builds.

Source Git and signature verification capture and revalidate
`/usr/bin/git` and `/usr/bin/gpg`. The public-key cache uses a private
user-owned directory; cached/configured keys are read as bounded stable
non-link byte snapshots, fetched keys are published privately without replacing
an existing path, and the exact captured bytes are copied into an isolated
temporary GPG home before import. Package archive member capture, ClamAV,
notification, makepkg, upgrade, and privileged-agent paths use their documented
trusted absolute executables. Package archive and ClamAV collection impose
their documented output/runtime bounds; source Git/GPG likewise use bounded
combined child output, timeouts, and isolated configuration. Their native
parser exposure remains a residual risk. The later makepkg handoff is neither
a parser sandbox nor a bounded build. Raw ClamAV stdout/stderr, human-readable
GPG diagnostics, and raw provider errors are not persisted as finding evidence.

These controls reduce path substitution, prompt-injected command authority,
and accidental secret retention; they do not sandbox a native parser. A defect
in AuraScan or an invoked parser can still be exploitable by hostile bytes.
Same-UID malware can attack user-owned configuration, cache, and state, and
root malware can replace AuraScan or the system tools it trusts.

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

## Foreground Policy-Gated Repair Agent

The Repair Agent is disabled beyond `guarded` tools unless the user configures
the compatibility access profiles `user-shell` or `root-shell`. Neither is a
general shell grant. The feature runs only in an interactive foreground
terminal. Root collectors, background services, pacman hooks, JSON workflows,
and the recovery environment cannot invoke it.

The model receives the retained redacted AuraScan context, the current
redacted question, a bounded in-memory conversation, and bounded terminal
results. Terminal output is redacted by default. Sending bounded raw output
requires typing `SHARE FULL TERMINAL OUTPUT` for that session. The model sees
at most 32 KiB per command and 128 KiB per session, within a 12,000-character
request. API keys and other AuraScan secrets are omitted from the executor's
minimal environment.

`user-shell` permits only allowlisted shell output/test builtins and absolute
read-only diagnostics under `/usr/bin` or `/usr/sbin`, running as the logged-in
user. `root-shell` adds policy-validated root access for those diagnostics and
constrained exact `/usr/bin/pacman` query, sync, or removal workflows. It
requires a root-owned policy opt-in plus the exact phrase
`GRANT AI ROOT REPAIR COMMANDS` for every session. The provider and
unprivileged assistant keep the API credential; the root broker receives no
provider configuration. Root capabilities are stored under
`/run/aurascan-agent/`, expire quickly, and are bound to the UID, originating
process/start time, terminal, retained-context fingerprint, and approval
ceiling.

Every exact model-authored policy-gated command requires a fresh foreground
confirmation, including a command proposed after the model reads earlier
terminal output. Legacy `whole-plan` and `session` settings are accepted when an
older configuration is loaded but are enforced as `each-command`; neither the
command-profile consent nor the root-session phrase authorizes later commands.

The provider has no direct shell tool. Its response must match a bounded exact
JSON schema. Before confirmation, AuraScan rejects every program outside the
allowlist, bare/custom diagnostic paths, mutating or escape-capable diagnostic
flags, remote references, network/remote-shell clients, Git, AUR/build front
ends, interpreters/loaders, decoding/evaluation, shell expansion, redirection,
and unsafe pacman operations. Repository package operations must name
`/usr/bin/pacman`, cannot target AuraScan directly, and cannot use `-U` or
alternate root/config/keyring/hook paths. Privileged broker calls revalidate
trusted package-managed `/usr/bin/sudo` and `/usr/bin/aurascan` identities each
time.

Before policy-gated root access, AuraScan creates a validated Btrfs/Snapper
snapshot when supported. Continuing without one requires typing
`CONTINUE WITHOUT ROLLBACK`. Snapshots cannot protect other disks, firmware,
credentials, networking, remote services, or every local configuration.

User audit records are stored under `~/.local/state/aurascan/agent/`; root
manifests are stored under `/var/lib/aurascan/agent/`. Directories use `0700`
and files use `0600`. They contain command hashes, redacted command renderings,
approval metadata, exit status, snapshot state, and bounded redacted output.
They do not intentionally retain API keys, questions, or AI answers and are
limited to 30 days or 50 sessions.

The policy gate does not authorize arbitrary model-authored code. Root package
repairs are still consequential: an approved pacman sync/removal can change
installed software and system state, and a policy/parser defect or unsafe
package transaction can cause damage. Read-only diagnostics may expose private
paths, configuration, logs, or credential-adjacent data in their output.
Redaction is best effort; the exact `SHARE FULL TERMINAL OUTPUT` phrase
deliberately increases what the provider receives. Typed grants, fresh command
confirmation, snapshots, and audits reduce accidental activation but do not
make every permitted query or package transaction harmless.

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
