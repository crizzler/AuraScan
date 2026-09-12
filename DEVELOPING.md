# Developing AuraScan

Run the test suite with:

```bash
python -m pytest
```

For a fresh checkout, install the test dependency group first:

```bash
python -m pip install -e ".[test]"
```

Syntax-only validation is also useful for quick security-focused edits:

```bash
python -m compileall aurascan tests tools
```

GitHub Actions runs the editable test install, compile check, complete pytest
suite, and both strict presenter audits on Python 3.8 and 3.14. Provider calls
are mocked; CI explicitly disables general, Instruction Guard, Incident, and
Recovery AI and never starts a live local model server.

## Signed runtime intelligence

The [runtime contract](tools/intelligence_repository/SCHEMA.md) and
[publisher workflow](tools/intelligence_repository/README.md) define a separate
`1.0` format for reviewed runtime indicators. Research intake never promotes or
publishes these records. Explicit redistribution permission and a review basis
are mandatory; public availability does not establish permission. Keep exact
observed malicious versions distinct from broader source-backed advisories.

One immutable snapshot belongs to each scan/audit. Matchers accept the captured
snapshot, and upgrade projections use the advisory identity/floor already bound
to the finding. New intelligence invalidates caches, trusted history,
`new-only` shortcuts, review fingerprints, and wrapper acceptance; do not reload
inside a matcher or mix generations. Stale verified records remain available
with shortcuts disabled. Corrupt active state reports incomplete coverage and
cannot silently become an allowed install. Freshness cannot authenticate the
host clock or reveal an unseen newer release during an offline scan.

The fixed unprivileged `aurascan-intel` account fetches bounded assets into
untrusted staging. A distinct privileged system service has a private network
namespace and activates only stable captured bytes verified by fixed trusted
GnuPG, exact packaged fingerprints, strict metadata, and rollback checks. The
active pointer and highest accepted sequence form one serialized durable
transaction. All scans use the protected system installation, including root
package hooks. Ordinary commands never fetch. The explicit updater bypasses
project/user dotenv loading, starts no AI, and uses no feed credentials.

An interrupted first activation can leave generation data without a committed
active pointer. This ambiguous state refuses automatic sequence-history reset.
Operator recovery must restore verified activation metadata and retained
sequence history from trustworthy evidence; deleting state to make a bundle
appear to be the first update is not a supported recovery procedure.

The optional daily timer ships disabled with an explicit systemd preset.
Package scripts must not enable/start it or contact the network. Root service
definitions use minimal environments and fixed entry points; the fetch account
cannot write the active store. Root activation has only the DAC read capability
needed to capture the fetch account's private staging files. Test these
boundaries with temporary roots and injected runners instead of changing host
accounts/services. Real detached-signature tests use disposable temporary keys.

Tray intelligence controls use asynchronous, fixed `/usr/bin/aurascan` status
and unprivileged `/usr/bin/systemctl` service requests, with a minimal child
environment, closed stdin, bounded output/runtime, and no shell. A fixed trusted
`/usr/bin/setsid --wait` detaches service clients from any controlling terminal
so systemctl cannot open a hidden terminal authentication prompt. Desktop polkit
authorizes service management; AuraScan installs no passwordless policy or
custom authorization grant. Two fixed network-isolated root oneshots delegate
timer enable/disable to the same administrative CLI checks. The tray never
becomes root. Terminating a waiting client does not cancel an already accepted
service transaction; services retain their own deadlines and status is reread.

Validate the `intelligence-status/1.0` display fields before rendering them;
never display raw stdout/stderr. The optional `--include-services` query reads
only selected local systemd properties. Use actual enabled/active timer state,
not an optimistic checkbox; inconsistent or unavailable state needs review.
`activated_at` comes from protected activation metadata and does not change on
an identical reimport. Service result properties may reset on unit unload and
must not be described as durable attempt history. Menu refresh is non-fetching.
Keep Quit guarded by both Instruction Guard and intelligence mutations, and
retire child processes/timers without letting late callbacks affect new work.
Test authorization failures, state disagreements and Qt adapters using injected
processes; do not start host services or request real privilege in tests.

Production feed/key configuration remains empty in v0.10.10. No CLI or
environment setting may inject keys, weaken verification, or choose a different
feed. Initial key replacement/revocation recovery requires an application
update, and this bounded protocol must not be described as TUF-compliant.
Schema/capability changes need an explicit migration preserving fail-closed
rights and rollback state. Same-UID/root compromise, native parser flaws,
publisher mistakes, and an absent live freshness oracle remain limitations.

Run `tests/test_intelligence_*.py`, publisher template tests, scanner/audit
parity and cache/review regressions, then the full source gates. The existing
Python 3.8/3.14 CI matrix includes the publisher tests. Validate new systemd,
sysusers, tmpfiles and packaging definitions without starting them. The v0.10.10
application release is **recovery-bearing** because this changes shared scanner
trust and handoff decisions; the release workflow requires a fresh validated
recovery build. Production key provisioning and feed publication remain
separate reviewed work, and package installation never enables updates.

## Maintainer-history evidence

For maintainer-history changes, the current runtime observes only PKGBUILD
comment text. Preserve the legacy snapshot `maintainer` field as annotation
data; it carries no AUR ownership authority. Use
`HIST-MAINTAINER-ANNOTATION-CHANGED` and `maintainer_annotation_changed` for
added, removed or edited comments, retaining MEDIUM/manual review and normal
scanning. Do not invent a timestamp cutoff or interpret missing comments,
restore/push narratives, Git authors, or adoption requests as platform state.
Future ownership acquisition must bind authoritative before-and-after package
base identity and maintainer state separately from code history. The existing
normalized ownership/adoption policy reasons still require conservative scanning;
the policy consumer does not authenticate the source of those reasons.

## Security intelligence and model evaluation groundwork

Use [Security model research](docs/SECURITY_MODEL_RND.md) for corpus admission,
model-neutral research roles, training/evaluation separation, immutable run
identities and the inert hypothesis-to-regression workflow. The separate
[security-data contract](security-data/README.md) defines versioned JSON
metadata and its offline validator. The separate
[intake CLI](docs/SECURITY_DATA_INTAKE.md) captures explicitly selected public
sources and fixtures into private quarantine, then records explicit reviews
without enabling training/evaluation or other use flags. Acquisition alone does
not create a validated record. Neither tool invokes models or exports operational
state. Keep private holdouts and generated manifests
outside the worktree. Existing public fixtures remain exposed regressions and
keep their current `expected.json` format.

For changes to this contract or intake, run `tests/test_security_data_*.py` plus the existing release
and CI contracts, review documentation links, validate `SKILL.md` frontmatter,
and run the applicable source gates. No model service or new runtime dependency
is required. Historical evaluation results must retain their exact inputs,
labels, detector/model configuration and coverage rather than being overwritten.

## Editor task and Git identity evidence

The PolinRider review uses [Socket's primary campaign tracker](https://socket.dev/supply-chain-attacks/polinrider)
as behavioral evidence, not an AUR compromise claim or a package-name blacklist.
Its counts are changing observations. The [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#run-behavior)
defines `runOptions.runOn: folderOpen`; workspace trust and automatic-task
permission remain execution prerequisites.

Keep `.vscode/tasks.json` analysis on structurally selected command fields,
using the same captured bytes as the scan identity. Repository snapshots retain
at most 32 task files, 1 MiB each and 4 MiB combined, through the existing
no-follow descriptor read. Ordinary repository pruning still applies; exact
declared local task files do not waive task inspection. Deep-static selects the
same path under its existing acquired-tree bounds and bypasses generic
raw-text shell matching for that JSON. JSONC comments and trailing commas are
supported; duplicate keys, malformed data, ambiguous dependency labels, cycles,
unresolved active variables or unsupported active syntax are coverage failures.
Use the bounded Linux task subset; never resolve extensions, execute tasks,
reopen command targets or treat task labels as active commands. A literal
interpreter/carrier execution correlation in a reachable automatic task is
CRITICAL; mere task or asset presence is neutral.

Do not generalize this into font validation, arbitrary JavaScript deobfuscation,
or a blockchain/RPC blacklist. Existing acquired JavaScript checks still have
their documented lexical limits; full RPC → decrypt → eval dataflow analysis
and standalone Instruction Guard task discovery are deferred. The new
regressions are exposed inert examples, not an estimate of campaign recall.

Git selector fragments participate in trust-diff identity. A selector change
must not qualify as ordinary URL version churn, and a non-full commit selector
must not get pinning reassurance. Resolve exact branch/tag namespaces to a
verified commit, detach by that hash and verify HEAD; persist only the resolved
commit identifier alongside redacted acquisition metadata. Keep deep-static
allow caching disabled. Default non-fetching scans cannot detect unseen remote
ref movement; do not invent history-rewrite findings from commit dates or
hosting reputation. Git revision verification authenticates neither author nor
content and does not prove the later makepkg build will use those bytes.

## Recovery release disposition

Every release must be classified in its release note and checklist as either
`recovery-bearing` or `package-only`. Recovery is optional at runtime in both
cases; this disposition says what the release publisher built and validated,
not what package installation enables.

A recovery-bearing release is mandatory when a change affects the recovery
runtime or recipes, recovery boot or image integration, the recovery package
set/build tooling, or a security boundary shared with recovery such as provider
validation or guarded AI response handling. A periodic refresh may also be
chosen to prevent the downloadable environment from falling too far behind the
host package. Other releases may be package-only, but their notes must name the
exact retained recovery image version/tag and SHA-256 and say explicitly that
the ISO and local-UKI gates were not rerun. Its packaged manifest must advance
`application_version`, declare `package-only`, retain and re-verify the exact
prior ISO version, filename, public tag URL, digest, and `release-ready` status,
and publish no newly relabeled recovery assets. A retained image may be at most
90 days old on the new release date; when it would exceed that window, the
release must become recovery-bearing. Do not reset `released_at` without
building and validating new bytes.

The packaged recovery ISO manifest uses the exact on-disk
`aurascan_recovery_iso/2.0` field set. Do not reinterpret the older six-field
`1.0` document or persist derived status/display fields into the manifest.
Runtime age is measured against the UTC date, with at most one day accepted as
bounded clock skew; dates farther in the future fail closed and the 90-day
refresh policy remains unchanged.

For a recovery-bearing release:

1. Prepare a clean, committed release candidate with the recovery download
   digest empty/build-required and the Arch source checksum temporarily set to
   `SKIP`. Use a fresh root-owned, non-writable checkout and fresh root-owned
   work and output directories inside a freshly provisioned, disposable, and
   externally CPU/RAM/disk-bounded Arch VM or host with no host disk or home
   share. Never elevate the builder over a user-writable release tree,
   profile, local package repository, work path, or output path. Disable every
   AI mode and use the fixed trusted tool paths and minimal environment
   documented by the recovery builder; never select an artifact from an older
   output directory. Invoke the QEMU harnesses only from the exact retained
   root-owned source snapshot printed by the builder. Selecting a
   user-writable harness is already unsafe before its internal checks run.
2. Build one hybrid x86-64 ISO and generate its SHA-256 sidecar and sorted
   package manifest from that same build. Treat the exact three files as an
   indivisible candidate and fail if the ISO is not strictly smaller than
   2 GiB (2,147,483,648 bytes).
3. Validate the finalized ISO under both SeaBIOS and OVMF UEFI. Build and boot
   the local UKI in ordinary OVMF and enrolled-key Secure Boot modes, including
   rejection of its unsigned counterpart. Run the documented deterministic
   storage, networking, package-repair, rollback, and bootloader fixtures plus
   the bounded privacy and expanded-image artifact checks, including normalized
   entry/link names, PAX metadata, and decoded libarchive xattrs. Empty/short
   explicit markers and short host identities fail closed. Booted platform
   scenarios are required when their subsystem changed or the release claims
   the live outcome; otherwise keep them visibly `NOT RUN`. Build the local UKI
   from the exact candidate code/package rather than whatever AuraScan version
   happens to be installed on the builder. A local UKI is
   machine/kernel/key-specific evidence, not a universal GitHub asset.
4. Record the exact release-candidate commit, then pin the tested ISO filename,
   public release URL, and SHA-256 in the packaged
   manifest, then commit. Reject the final candidate if its manifest remains
   `build-required` or release metadata still says pending. Create the
   immutable annotated tag only after that commit is final, create a draft
   GitHub release, upload exactly the ISO, `.iso.sha256`, and
   `.iso.packages.txt`, verify their remote names, sizes, and digests, and only
   then publish the release. Do not rebuild the ISO after pinning: the final
   pre-tag delta from the recorded candidate is limited to the packaged ISO
   manifest and bounded release metadata, and the pinned digest must still
   match the retained candidate bytes. Push this branch candidate and require
   the Python 3.8/3.14 GitHub Actions matrix to pass before creating the tag.
   Require the exact tag's matrix to pass before publishing the draft release;
   skipped, cancelled, stale, or unrelated runs do not satisfy either gate.
5. Download and hash the exact public tag archive, replace the Arch recipe's
   `SKIP`, regenerate `.SRCINFO`, validate the trusted package, and only then
   update GitHub `main` and the separate AUR repository. Never move or rewrite
   the public tag to include this post-tag package checksum commit.

Do not report a recovery or release gate as passing unless it was actually run
against the exact candidate being published. A missing privilege boundary,
firmware, required boot test, deterministic scenario, artifact audit, or size
check stops a recovery-bearing publication; it does not silently turn into a
successful package-only release. An optional booted platform scenario may be
omitted only with an explicit public `NOT RUN` limitation and no corresponding
live-support claim.

## Real-world warning tuning

The AUR warning tuning helper is an opt-in networked check. It fetches only
PKGBUILD/.SRCINFO metadata from aur.archlinux.org and does not download package
sources, run makepkg, clone repositories, fetch keys, or execute package code.

```bash
python tools/aur_warning_tune.py
python tools/aur_warning_tune.py --json yay paru google-chrome
python tools/aur_warning_tune.py --warning-budget 4 yay paru syncthing
python tools/aur_warning_tune.py --package-list-file tools/package_lists/aur-warning-tune-mixed.txt --limit 100
python tools/aur_warning_tune.py --output-json tools/reports/aur-tune.json --output-markdown tools/reports/aur-tune.md --category-label mixed-aur-sample
```

The helper combines source-metadata analysis with deterministic PKGBUILD text
rules. It summarizes eval warnings, systemd unit notes, systemd auto-enable or
user-service warnings, cron warnings, visible warning group counts, packages
over the selected warning budget, median and p95 warning volume, hidden
lower-risk notes, top noisy rule IDs, top noisy rule families, package examples
for noisy rules, severity counts, manual-review counts, hard-blocker counts, and
tuning notes. A warning budget is a UX tuning threshold for how many visible
warning groups are comfortable in default output; it is not a security bypass.

Useful tuning gates:

```bash
python tools/aur_warning_tune.py --package-list-file tools/package_lists/aur-warning-tune-mixed.txt --fail-if-average-visible-warnings-above 2
python tools/aur_warning_tune.py --package-list-file tools/package_lists/aur-warning-tune-mixed.txt --fail-if-any-package-over-budget 4
```

Treat these gates as reporting checks for UX regressions, not as package safety
decisions. A noisy package may be harmless, and a quiet package is not proven
safe.

Metadata-only tuning has important limits: it cannot see downloaded source
archives, generated files, install-hook files that are not present in the
fetched PKGBUILD text, upstream repository contents, package runtime behavior,
or local package-manager transaction context. Use it to spot noisy static rules,
not to decide whether a package is safe. Live AUR sampling is intentionally not
part of normal pytest; deterministic fixtures should cover every rule tuning
change.

## Presenter coverage audit

Rule metadata and presenter templates are optional. Unknown rule IDs must still
render safely with friendly fallback wording, and normal tests should not fail
just because a new rule has not been cataloged yet.

The maintainer audit helper parses local Python files only. It does not run
package code, run analyzers, use the network, download sources, fetch keys, or
execute GPG.

```bash
python tools/audit_presenter_coverage.py
python tools/audit_presenter_coverage.py --min-severity MEDIUM
python tools/audit_presenter_coverage.py --json
python tools/audit_presenter_coverage.py --strict
python tools/audit_presenter_coverage.py --strict-medium
```

`--strict` exits non-zero when a discovered HIGH/CRITICAL rule relies only on
fallback presenter wording.
`--strict-medium` applies the same gate to MEDIUM and higher rules. This is
useful before release tuning, while the default audit remains advisory so
low-risk fallback notes do not block routine development.

## First-run setup and doctor

`aurascan init` is the interactive setup path for user-level configuration. It
writes only `~/.config/aurascan/.env`, creates the config directory with `0700`,
and writes the env file with `0600`. Do not add command-line API key flags;
secrets must be entered through hidden input or preexisting environment/config.

Wizard-created configs must set `AURASCAN_AI_ENABLED` explicitly. AI-disabled
setup writes `AURASCAN_AI_ENABLED=0`. Enabled AI setup may write
`AURASCAN_AI_PROVIDER`, `AURASCAN_AI_MODEL`, and one provider-specific key such
as `AURASCAN_OPENAI_API_KEY`. Legacy `AURASCAN_AI_KEY` remains supported so
existing users do not lose behavior.

Agent Instruction Guard setup is separately explicit. The wizard may write
`AURASCAN_INSTRUCTION_MONITOR_ENABLED`,
`AURASCAN_INSTRUCTION_AI_ENABLED`, and
`AURASCAN_INSTRUCTION_SCAN_MODE=agent-surfaces|all-markdown`. Installing the
package or selecting a general AI provider must not enable either Instruction
Guard timer. Doctor reports monitor state, notification availability, private
state permissions, AI consent and provider readiness, and service/timer health
without scanning the real home or contacting a provider.

`lmstudio` and `llamacpp` are explicit local AI provider IDs using the shared
OpenAI-compatible chat-completions transport. Their defaults are respectively
`http://127.0.0.1:1234/v1` and `http://127.0.0.1:8080/v1`. The wizard may save a
loopback override as `AURASCAN_AI_BASE_URL` and an optional Bearer token as
`AURASCAN_LOCAL_AI_API_KEY`. Do not require a fake key for a local server with
authentication disabled, but do require `AURASCAN_AI_ENABLED=1`; keyless local
configuration must not revive the old implicit-enable behavior.

Local-provider URL handling is part of the security boundary. Accept only
loopback HTTP(S) endpoints without userinfo, query, or fragment components;
bypass environment proxies; pin plain-HTTP `localhost` to `127.0.0.1`; refuse
HTTP redirects; use bounded response reads
and timeouts; and never fall back to a cloud endpoint. Do not start a server,
download a model, enable tools or MCP, or send a live request from tests. Use
injected openers and assert that credentials do not appear in diagnostics,
exceptions, or serialized details.

All package-AI input is attacker-controlled data. Send only a bounded,
line-numbered JSON evidence object and give that model no tools, URL authority,
or command channel. Accept an exact schema containing only the raise-only
verdict, allowlisted behavior families, and references to supplied lines.
Reject extra fields, free prose, snippets, URLs, commands, unknown labels,
duplicate keys, and out-of-range lines without retaining raw output. A
no-additional-concern response must never be presented as clean, safe, trusted,
or approved and cannot suppress deterministic findings. Cloud and local
provider transports both refuse redirects; provider errors must be normalized
before they reach reports, caches, audit logs, or terminals, and credentials
must never appear in a request URL.

When AuraScan runs as root from a sudo-launched pacman hook, config loading may
also read the invoking user's `~/.config/aurascan/.env` from `SUDO_USER`.
Unattended or direct-root hook contexts should use `/etc/aurascan/.env`.

`aurascan doctor` is diagnostic. It must not contact AI providers unless
`--check-ai` is supplied, and it must never print secret values. Missing
optional tools should be warnings unless the checked workflow cannot proceed.
Doctor should report upgrade preflight and config drift assistant config state,
including invalid env values, without reading or printing config file contents.
For local AI, ordinary doctor output may validate the stored loopback URL and
optional-token state locally; chat connectivity is allowed only under the
explicit `--check-ai` request.

Recovery reuses validated provider configuration but does not start or forward
a local inference server. Loopback there names the recovery environment, not a
server running on the installed target. A missing local endpoint must preserve
offline deterministic recovery and must not trigger cloud fallback.

Manual hook setup from `aurascan init` is allowed only for the local admin hook
path `/etc/pacman.d/hooks/aurascan.hook`. The installer must refuse hook writes
unless `/usr/bin/aurascan` exists and the template is release-safe. Packaged
installers should still own `/usr/share/libalpm/hooks/aurascan.hook`.

Package install scripts must stay non-interactive. They may print advisory
first-use guidance, but they must not run `aurascan init`, run `aurascan
doctor`, request secrets, write user config, install local `/etc` hooks, run
makepkg, inspect packages, or contact the network during install or upgrade.

## Agent Instruction Guard

The September 8, 2026 [GTIG DUSTMAKER report](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai)
describes poisoned agent configuration, scanner-directed loader comments, and
compromised publishing with valid attestations. It supplies no exact affected
package range suitable for a new AuraScan package denylist. Static matches
cannot attribute this campaign or establish execution or an AUR compromise.

Cursor discovery includes `.cursor/rules/**/*.mdc`, `.cursorrules`,
`.cursor/mcp.json` and `.cursor/permissions.json`. Reuse bounded discovery,
stable reads, continuation, machine-bound enrollment and content correlations;
do not run Cursor or any collected command. Rules use the Markdown analyzer,
including frontmatter descriptions; JSON configuration uses structural fields,
never metadata prose as command evidence. These files remain manual-only for
disable/restore. The analysis-evidence cache version advances to 1.4 so old
approved MCP analysis cannot suppress newly supported semantics; persisted
report/rule schemas remain compatible and package-scan versions are unchanged.

Use the official [Cursor rules](https://prod.cursor.com/docs/rules),
[MCP](https://prod.cursor.com/docs/mcp) and
[permissions](https://prod.cursor.com/docs/reference/permissions) contracts.
Approval-free MCP wildcard authority warrants HIGH review, independently of
maliciousness. Ordinary terminal entries, remote endpoints or authentication
placeholders alone are neutral. Malformed, ambiguous or unsupported active
configuration is coverage, with no interpolation, credential lookup, server
launch or network resolution. Do not claim to calculate merged user/team policy
or Cursor run-mode enforcement. Plugin manifests/component resolution, CLI
permissions and arbitrary MCP implementation analysis remain deferred.

Package AI is not summary-only: it can receive bounded numbered PKGBUILD text
or captured built-package `.INSTALL` text, including comments. Adjacent declared
hooks are inspected deterministically; arbitrary acquired JavaScript is not
sent through this package-AI path. Provider refusals or malformed replies must
preserve deterministic findings and the existing AI inspection-failure blocker,
without persisting rejected prose. Instruction Guard AI instead receives fixed
evidence without file contents. Regression tests use inert scanner-control
comments and mocked refusals, not the report's adversarial subject matter.
No vocabulary blacklist or speculative leading-comment classifier is added.
Source-signature verification cannot waive deterministic findings; AuraScan
does not currently implement SLSA attestation verification. An attestation
claim in package metadata cannot grant trust either.

`aurascan instruction-audit` is a static, unprivileged review surface for
AI-agent control files. It is not part of package scan rule versioning. Its
report and rule contract starts at `instruction_guard_report/1.0` and rule
version 1.0; changes to the existing package scanner must continue to follow
that scanner's independent versioning rules.

Default discovery recognizes `AGENTS.md`, `AGENTS.override.md`, `SKILL.md`,
`CLAUDE.md`, `CLAUDE.local.md`, and Claude rules, commands, agents, skills,
memory, settings, hooks, MCP/plugin manifests, and text scripts/resources owned
by a discovered skill. `--all-markdown` adds other Markdown files to content
analysis only; it must not create integrity-baseline entries for them. Follow
explicit Markdown imports and final file symlinks only when the resolved regular
file remains inside an allowed root. Do not traverse symlink directories.

CodeWhale project `.codewhale/config.toml` and legacy `.deepseek/config.toml`
are baseline-eligible configuration surfaces, never standalone-disable targets.
Exclude the actual user-global copies at `HOME/.codewhale/config.toml` and
`HOME/.deepseek/config.toml`: their shell opt-in is legitimate user policy and
they may contain authentication data. Tests inject HOME inside temporary roots;
never consult real credential bytes to distinguish these roles.
`agent_config.py` reads a bounded TOML subset using only the standard library on
Python 3.8+. Supported strings, quoted keys, ordinary numbers/booleans, arrays
and simple tables are parsed structurally; top-level shell enablement alone
selects the execution-authority review rule. Comments, strings containing
examples, table-scoped lookalikes and false values must remain negative.
Unsupported constructs (including multiline strings, inline tables, dates,
dotted assignments and arrays of tables), invalid shapes, duplicates and
limits are incomplete coverage; do not regex-search them for active grants.

Project instruction references preserve decoded literal filenames, including
spaces and `#`, and their physical declaration lines. Bind each imported
resource and recursive import to the containing project, not a broader selected
home. Nearby project config presence also narrows independently discovered
controls before the config page is processed; it does not establish a declared
import or change content-only Markdown into baseline work. Bound no-follow
ancestor inference by the scan deadline and retain unread work when it expires.
Bind cached import semantics to prior project context, including config removal.
Preserve origin in bounded, cycle-bound pending cursor records. Private cursor
schema `1.1` carries project context, while validated legacy
`1.0` string cursors remain readable and are upgraded on the next write. Older
AuraScan binaries refuse `1.1` cursors rather than widening their boundary.
Revalidate references on every scan and continuation. Refuse credential-file references and outside-project paths
without opening them. Do not normalize away parent components before checking
symlinks; parent traversal and config/resource links remain manual-only.
Deferred findings attached to a resource must not borrow the config's line
number. Keep unsafe raw reference values out of reports and manifest imports.
Instruction analysis evidence is now `1.4`; the report/AI contracts remain
unchanged.

Discovery must prune cache, trash, VCS, dependency, and virtual-environment
trees, and bound directories, entries, candidates, file size, and elapsed time.
Persist a continuation cursor when the root is too large for one run. Candidate
reads use no-follow semantics, validate owner and regular-file type with
`fstat`, and reject replacement detected during the read. Never execute,
import, source, render, or deserialize a file into executable objects.

Instruction rules should correlate behaviors rather than flag isolated tool
names. Required behavior families include fetch plus execution, credential
access plus archive/upload, automatic activation plus concealment, persistence
or self-repair plus a dangerous action, obfuscation plus decode/eval/exec, and
privilege/password/SUID/sudo-policy abuse. Dangerous hooks, broad tool grants,
and Claude dynamic `!command` blocks are active surfaces. Parsing should
separate those constructs from fenced examples, quoted documentation, HTML
comments, negation, YAML frontmatter, and invalid JSON configuration. Static
evidence must not be worded as proof that an assistant executed an instruction
or that compromise succeeded.

Preserve original, one-based physical line locations while normalizing active
text. A content finding should carry bounded deterministic line ranges,
semantic behavior labels, and a fixed reason, but no source snippet. For a
multi-line correlation, retain the role contributed by each range rather than
copying the complete correlated family set onto every location: for example,
identify the retrieval range separately from the later execution range while
the finding still explains why those roles matter together. File-level
integrity, read, parser, and legacy-report findings must explicitly omit a
precise location when one cannot be established safely. Never reconstruct,
print, or persist the source text to make the explanation more vivid.

Keep suspicious-content risk, integrity changes, neutral baseline enrollment,
and coverage limitations as four separate presentation concepts.
`review_required` remains their compatibility aggregate and must not be
rendered as if it always means malware was detected. Derived status should
identify security attention, coverage action, baseline enrollment, or clear
state explicitly. The terminal renderer should lead with their separate
counts, avoid presenting the report's fallback LOW value as a
suspicious-content severity when there is no content finding, and group
suspicious instructions ahead of changed/unsafe files, clean first-seen
enrollment, and coverage limitations.
Wrap prose and long paths predictably for narrow terminals without corrupting
IDs, line ranges, or JSON output. A truncated page must be labeled as incomplete
and explain that its committed continuation remains pending.

Suspicious first-seen files alert immediately; otherwise safely read clean
first-seen recognized files form one neutral enrollment inventory. Do not let
that inventory alone create a danger tooltip or urgent notification. Render it
as baseline setup and explicitly say that first-seen means no machine-bound
approval exists, not that suspicious content or malware was found. AI remains
`not-needed` when a clean first-seen file has no eligible deterministic content
finding and can never authorize enrollment. For eligible findings, place a fixed
deterministic explanation beside its exact evidence roles and show only an
evidence-mapped AI rationale labeled as advisory. AI prose cannot replace the
deterministic explanation, create or move a location, establish trust, or enter
the integrity-only inventory. Disclose how many displayed findings received a
bounded AI explanation, and label malformed or incompletely parsed
configuration as scan coverage rather than suspicious content. Give safely
approvable new or changed files a concrete next step; unsafe identities must
remain manual-only. A batch clean-enrollment action requires explicit
confirmation and a complete coverage-clear report. It must revalidate every
selected regular file's parent chain, owner, inode, metadata, and hash before
one serialized private-state transaction, aborting the entire action for any
stale, changed, suspicious, restored, or unsafe baseline candidate. Clean
content-only Markdown is analyzed but excluded from enrollment; a content or
coverage finding in it still blocks the transaction. Bind interactive actions
to the exact displayed report and hash, and fail closed on an interrupted
transaction marker. Recovery must use a complete deterministic scan of the
marker-bound root, revalidate every recorded target without cache reuse, and
retain the marker across unrelated roots and partial continuation pages. Store SHA-256 plus
device/inode, size, timestamps, mode, owner, and symlink state. An approval is
valid only for the exact content and a binding derived from machine identity
plus UID. Corrupt, symlinked, wrongly owned, or permission-weakened state must
fail closed without overwriting it. State, reports, manifests, queued AI jobs,
alerts, and disable receipts belong under an injected
`$XDG_STATE_HOME/aurascan/instruction-guard/` root with private directory/file
modes.
Keep history bounded: retain the current report plus at most the newest 32
reports within a 256 MiB aggregate budget, and at most 2,048 secret-free alert
envelopes. Retention may discard old presentation records, but it must not
approve a file, weaken manifest review state, or leave a pending AI job pointing
at a deleted report.

The offline monitor service runs after login and every five minutes with
`PrivateNetwork=yes`, a read-only home, private writable state, low CPU/I/O
priority, and all supported AI credentials unset. Detection is a successful
service run: background capture records findings and exits zero so systemd does
not call a security alert a crashed unit. A separately enabled assistant timer
processes at most one pending job per run. Its prompt contains at most 12 KiB
of opaque evidence IDs, fixed deterministic reasons, semantic behavior labels,
and deterministic locations; it contains no path or source snippet, grants no
tools, and requires strict JSON. AI rationales must map back to supplied
evidence IDs. AI cannot create or change line locations, lower deterministic
severity, trust an integrity change, claim execution or compromise, or supply
executable commands. Disabled AI must make zero provider calls; malformed or
timed-out output preserves deterministic findings and their locations.

The updater tray's checkable monitor and AI controls must remain thin clients
over `aurascan instruction-audit --status/--enable-*/--disable-*`. Run those
commands with an asynchronous, no-shell child process; retain its lifetime,
serialize changes, bound output and runtime, and refresh state after each
operation and whenever the menu opens. Status exit codes 0 and 1 are both valid
JSON states because pending review is not a control failure. Never call the
configuration setters or live systemd synchronously from the GUI thread. Do
not expose child stdout/stderr in notifications, tooltips, or other public tray
state. Disable or defer the tray's own Quit action while a mutating control is
running so parent teardown cannot interrupt a rollback. Provider readiness and
transaction rollback remain owned by the CLI.

The tray's agent-file action opens foreground guided triage. Suspicious and
changed/unsafe states use attention or critical presentation; incomplete
coverage is an explicit scan action; clean first-seen enrollment is a neutral
setup/due state. Triage may offer only fixed core actions such as exact-hash
approval, confirmed eligible disable, rescan, leave, and quit. It must not
execute instruction content, launch an editor, or turn AI prose into an action.
Background services and JSON workflows remain noninteractive.

Desktop notifications and tray/public alert state are secret-free: retain only
generic severity/count/review wording, never paths, snippets, usernames,
credentials, or AI output. Deduplicate by candidate identity, content hash, and
rule set. Acknowledgment suppresses duplicate notification only and never
approves content. Resolve notifications through the shared trusted-tool
boundary: only captured and revalidated `/usr/bin/notify-send` may run. Its
absence is a notification-delivery limitation, not a reason to discard private
CLI/tray review state. Clean baseline enrollment never creates an alert;
coverage notifications must use neutral scan-attention language rather than
claiming that a file is risky or malicious.

Confirmed disable is intentionally narrow. Only an unchanged, user-owned,
standalone regular instruction Markdown file may be atomically renamed beside
itself to a hidden non-discoverable name. Settings, hook configuration, plugin
manifests, scripts, shared configuration, and symlinks are manual-only. The
private receipt must bind original and disabled paths, report/action IDs,
inode, hash, metadata, and timestamp. Restore requires unchanged disabled
content, an absent original path, and a still-safe parent directory, then
rescans and returns the file to unreviewed state. Do not add automatic
quarantine.

Tests use injected temporary roots and defanged `example.invalid` fixtures.
Cover positive behavior correlations and benign style/security documentation,
negated commands, ordinary hooks, and fenced examples. Also cover imports,
Unicode and invalid encodings, BOMs, binary/oversized files, inaccessible and
deep trees, truncation/cursors, symlinks, FIFOs, atomic replacement and
mid-read races, same-mtime changes, incremental hashing, machine-bound
approval invalidation, transactional clean batch enrollment and race refusal,
corrupt state, alert deduplication, and exact disable/restore refusal and round
trips. Mock AI, systemd, tray, and
notifications; tests must not scan a real home, start a model, contact a
provider, require root, or invoke live systemd.

Presentation tests must cover enrollment-only, suspicious-only, mixed, changed,
coverage-limited, continuation, and legacy reports. Assert that clean first-seen
files are never labeled as suspicious; contributing ranges retain their exact
one-based locations and per-range roles; deterministic and advisory AI reasons
remain distinct; narrow-terminal wrapping preserves IDs and meaning; `--json`
remains schema-stable and unwrapped; and source snippets, credentials, URLs,
terminal controls, and rejected or unmapped AI prose never enter review output.
CLI and tray tests must also cover guided prompt cancellation/EOF, batch
all-or-none behavior, neutral setup routing, conservative legacy status, and
noninteractive/background refusal to prompt.

Document the residual boundary in user-facing changes: this is periodic
detection, not pasted-command/link preflight, privileged fanotify or process
interception, or a same-UID containment mechanism. Same-UID malware can attack
user state and root malware can defeat the monitor.

## Curated Fixture Pack

The curated fixture pack lives under `tests/fixtures/curated_packages/`.
It provides safe, deterministic AUR-style scenarios for regression testing
without live AUR access, package installation, root, network, real makepkg, or
package code execution.

Run the fixture matrix with:

```bash
.venv/bin/python -m pytest -q tests/test_curated_fixtures.py
.venv/bin/python -m pytest -q tests/test_deep_static_fixtures.py
```

Each scenario has an `expected.json` manifest. Static and wrapper fixtures keep
`PKGBUILD` at the scenario root. History fixtures use `previous/PKGBUILD` and
`current/PKGBUILD`, with optional `.INSTALL` files.

Useful manifest fields:

```json
{
  "scenario": "curl_pipe_shell",
  "category": "malicious_defanged",
  "scan_modes": ["fast", "wrapper"],
  "package_name": "curated-curl-pipe-shell",
  "package_version": "1.0",
  "expected_rule_ids": ["NET-EXEC-001"],
  "expected_phases": ["pkgbuild_static"],
  "expected_min_severity": "CRITICAL",
  "expected_action": "block",
  "expected_makepkg_invoked": false,
  "expected_wrapper_action": "scan_blocked"
}
```

Expectations are intentionally partial. Prefer asserting rule ID subsets,
minimum severity, wrapper action, makepkg invocation, selected phases, and a
few stable terminal snippets. Avoid exact full JSON or terminal snapshots.

Fixture safety rules:

- Keep malicious fixtures defanged.
- Put suspicious commands inside `echo` strings or comments when possible.
- Use `example.invalid` for all fixture URLs.
- Use fake private paths only as static detection strings.
- Do not include destructive commands, real attacker domains, reverse shells,
  or live public IPs.
- Do not add tests that call real makepkg, use `shell=True`, install packages,
  require root, or write to the real user home.

Current coverage includes benign source metadata, pinned Git sources, signature
metadata, benign install hooks, curl/wget pipe-to-shell, base64-to-shell,
credential path references, env secret references, SUID chmod patterns, weak
checksums, SKIP archives without signatures, suspicious install hooks,
ambiguous split-package update context, normal version bumps, source host
changes, combined supply-chain changes, PGP removal, checksum weakening,
dependency additions, install-hook changes, build-function changes, deep-static
archive traversal, absolute archive paths, symlink/hardlink archive escapes,
too-many-files archives, oversized archives, nested archive depth limits,
isolated PGP verification outcomes, suspicious `setup.py`, `package.json`
install scripts, token-reference source text, vendored dependency directories,
minified generated-looking files, eval-chain package logic, systemd unit-file
packaging, systemd auto-enable/start behavior, user-level systemd persistence,
cron file installation, crontab command use, cron `@reboot` entries, privileged
sudo execution from install hooks, non-executable extensionless shebang
scripts, dot-prefixed install-hook AUR repository propagation, and deep-static
systemd unit/auto-enable/user-persistence split behavior.

The deep-static fixture set lives under
`tests/fixtures/curated_packages/deep_static/`. Its archives, detached
signatures, and test public key material are generated under pytest temp
directories by `tests/helpers/archive_fixtures.py`; committed fixture files are
text-only templates and manifests. Deep-static fixture tests must use local
sources, temp-only key material, offline source policy, no keyserver access, no
real makepkg, no package-code execution, no root, and no writes to the user's
real home or GPG keyring.

Deterministic and deep-static eval/systemd/cron rules are intentionally focused.
Plain systemd unit-file packaging is lower severity because many daemon
packages install unit files legitimately. Automatically enabling or starting
services, writing user services, creating cron entries, or using `crontab` is
treated as manual-review behavior because it can create background persistence.
These findings do not prove malware by themselves; they mean the package
deserves review before building or installing.

When adding more deterministic fixtures, keep false-positive pressure in mind:
avoid matching pure documentation comments, keep benign service packaging
separate from auto-enable/start behavior, and prefer narrow rules for behavior
that changes background execution. Fixture tests must remain static-only: no
real makepkg, no package-code execution, no live AUR access, no root, and no
network requirement.

Remote-access detections should correlate independent behavior. A common daemon
or command such as `tailscaled`, `sshd`, or `systemctl` is not a backdoor signal
on its own. Require a remote-access anchor plus another privilege, persistence,
or anti-forensics behavior, retain exact incident indicators as separate rules,
and emit secret-free evidence labels. Test the malicious chain, ordinary tool
usage, comments/messages, missing-anchor combinations, and auth-key redaction.

Host-indicator tests must use an injected temporary root. Keep reads bounded,
refuse symlinked indicator files, never execute an artifact, and distinguish an
exact path match from content-validated or multi-artifact correlation. A host
finding should recommend trusted-media investigation without claiming that a
static artifact proves successful attacker access.

### AUR repository propagation

`SUPPLYCHAIN-AUR-REPO-PROPAGATION-001` is a deterministic package-control-text
correlation, not a general ban on Git publishing. Restrict it to PKGBUILD text
and declared install-hook text. Require an AUR Git target, repository mutation
or staging, and a non-dry-run `git push` bound to that AUR endpoint or configured
remote; treat repository enumeration, loops, dot-prefixed hooks, and
SSH-agent/key references as supporting evidence only. Comments, quoted
documentation, AUR clone/fetch operations, pushes explicitly bound to other
hosts, and any one signal alone must remain negative cases.

Do not apply this rule indiscriminately to acquired deep-static source. An
upstream project may legitimately contain maintainer release tooling, and
source presence alone does not establish that package build or install logic
invokes it. If future call-path analysis can prove invocation from package
control text, add that evidence explicitly rather than weakening the phase
boundary.

The committed curated fixture uses a dot-prefixed hook and
`AUR_HOST_PLACEHOLDER`. Its wrapper test substitutes `aur.archlinux.org` only
inside a temporary copy and uses a fake makepkg runner. Never put working
credentials, attacker infrastructure, or executable test setup around that
fixture.

### Filesystem repository provenance

The always-on repository provenance pass is distinct from both source-array
acquisition and acquired-source deep-static analysis. Starting from the
captured PKGBUILD's parent, enumerate only bounded, stable, regular-file
snapshots without following a symlink or invoking Git. Describe the result as
files observed alongside the PKGBUILD; filesystem presence does not prove that
Git tracks a file or that the AUR distributed it. The normal walk prunes VCS
internals, named cache/dependency directories, and root generated `src/` and
`pkg/` trees. Root package/source archives are captured but treated as
generated output, so their mere presence is suppressed. Entry, regular-file,
artifact, per-file, total-byte, depth, required-path, and elapsed-time limits
must fail closed with
`AUR-REPO-INSPECTION-INCOMPLETE-001` rather than silently reducing coverage.

Pruning is an enumeration policy, not a path-based trust grant. Before the
snapshot, collect supported, statically resolved checkout paths used by
transfer, execution, interpreter/loader, or permission-changing package logic.
Capture those required paths with the same component-by-component no-follow
checks even when they cross a normally pruned directory; an exact required
directory is traversed within the same bounds. A missing path does not invent
an artifact, but an ambiguous required path, unsafe component, parser limit, or
replacement during capture is incomplete inspection. Generated artifacts
reached this way may participate in an exact HIGH/CRITICAL correlation even
though uncorrelated generated output has no MEDIUM presence finding.

Recognize supported executable and archive carriers from bounded magic bytes,
including ELF, PE, Mach-O, and the implemented opaque-archive signatures. Do
not trust extensions, extract archives, invoke a native file-identification
tool, make a network request, or execute content. Exclude exact literal local
checkout files covered by a supported `source=()` declaration from artifact
classification; the repository manifest still binds their observed identity,
while normal source metadata and explicit deep-static workflows own their
provenance and content inspection. Treat statically proven VCS checkout roots
as source-owned directory subtrees during the ordinary walk rather than
enumerating an already-populated upstream cache. An exact statically required
child overrides that subtree exclusion and receives the ordinary bounded
no-follow capture; a symlink or wrong-type checkout root fails closed. An
ambiguous source declaration must retain the existing fail-closed source-parser
behavior rather than guessing an exclusion. In particular, a normally declared
upstream binary archive does not receive this repository-embedded finding
merely because its local cache file has archive magic; checksum and acquisition
policy remain separate checks.

Retain the identity of every captured regular file and directory and revalidate
all of those paths after traversal under the original deadline. This detects a
one-time mutation after an early subtree was read, but it is revalidation, not
an atomic filesystem snapshot: a same-UID process can still race after the
final check and root can replace the scanner or its inputs.

Keep the correlation tiers separate:

- `AUR-REPO-OPAQUE-ARTIFACT-001` is MEDIUM, non-hard-blocking,
  acceptance-eligible manual-review presence evidence.
- `AUR-REPO-OPAQUE-BINARY-001` is HIGH and manual-review eligible only when
  static package control text installs, copies, or moves the exact artifact into
  `$pkgdir`, including a descendant of an exact recursively transferred
  repository directory. Recursive inclusion alone does not prove the final
  child path when the destination may already be a directory.
- `AUR-REPO-OPAQUE-BINARY-EXEC-001` is a CRITICAL non-reviewable blocker only
  when PKGBUILD or declared install-hook control text invokes or code-loads the
  exact artifact, invokes its exact installed destination, or requests
  SUID/SGID privilege bits for that artifact or destination.
- `AUR-REPO-INSPECTION-INCOMPLETE-001` is a HIGH non-reviewable coverage
  blocker, not a malware verdict.

Bind the stable repository manifest/status to cache identity, wrapper
revalidation, review fingerprints, history, and trust comparison before any
cache or fast-path allow. Tests must cover binary-only replacement with an
unchanged PKGBUILD, no-follow traversal, pruning, all bounds, magic variants,
literal source exclusions, path aliases accepted by the command parser, and
the full severity truth table. Keep icons, fonts, firmware, generated test
data, inert archives, and checksummed upstream binary-package sources as
negative or presence-only cases. Fixed evidence labels must not disclose file
bytes, command snippets, or secrets. Local verbose terminal review should make
a correlation actionable by showing the sanitized control-file path and
one-based line plus a short artifact SHA-256 prefix; presence review may show
the sanitized observed path and the same short identifier. Never present this
technical locator as proof that an artifact is malicious, committed, installed,
successfully executed, or responsible for compromise.

The command and source views are deliberately bounded static approximations,
not Bash or makepkg evaluators. Only supported exact path chains can establish
HIGH/CRITICAL correlation; explicitly rooted ambiguity and parser/bound failures
must block as incomplete where the implementation can identify them. Dynamic
runtime path construction, unsupported loaders/decoders, nested or encrypted
archive contents, polyglots, steganography, and unrecognized magic remain
residual limits. A clear result is therefore not a provenance or safety
guarantee, and adversarial builds still belong in a disposable,
resource-limited environment.

### pnpm metadata and installed build-tool evidence

The local build-tool guard lives in `aurascan/core/pnpm_buildchain.py`; it
consumes captured PKGBUILD/declared-hook shell text and inspects only the local
pacman database for relevant dependency operations. Use bounded component-wise
no-follow reads, detect replacement, and compare validated upstream `pkgver`
with trusted bounded `/usr/bin/vercmp`. Arch epochs and package revisions do
not change upstream advisory ranges. Unknown/custom/pre-release versions,
ambiguous tool selection, or unavailable comparison fail closed as coverage.
Never execute pnpm or infer the selected future binary from a pacman record.
Relevant scans bypass cache and update-only skips cannot waive a blocker;
wrapper revalidation precedes the final package snapshot capture.

`aurascan/analyzers/npm_metadata.py` inspects only acquired decoded name fields.
Keep npm scope/name syntax and independent filesystem containment checks
separate. A valid archive layout or absent lifecycle script cannot clear
traversal in the internal manifest. The bounded standard-library YAML subset
supports literal block/flow mappings, scalar sequences, and quoted scalars for
lockfile versions 5.3, 5.4, 6.0, and 9.0. Reject duplicate fields, aliases,
anchors, tags, merge keys, multiline construction, unsupported dependency
identities (including unimplemented registry/file/Git keys), and resource
limits as `NPM-METADATA-INSPECTION-INCOMPLETE-001`. Unsupported metadata must
not be silently accepted or labeled malware. Ordinary scoped names,
supported peer suffixes, comments, and unrelated fields are negative cases.

The two upstream pnpm advisories were verified on 2026-09-06:
[lockfile name traversal](https://github.com/pnpm/pnpm/security/advisories/GHSA-c59q-g84q-2gj5)
and [dependency manifest traversal](https://github.com/pnpm/pnpm/security/advisories/GHSA-vq4v-j7r6-jq4m).
This rule does not rely on Arch's tracker currently listing an issue and does
not claim an AUR exploitation campaign. Tests inject database roots/version
comparison and use inert local tarballs; neither pnpm nor package code runs.

### Emergency vendor advisory evidence

`aurascan/core/security_audit.py` consumes the deliberately small reviewed
vendor-advisory mapping from the operation's captured runtime-intelligence
snapshot for gaps before distribution advisories arrive. It uses captured
installed package names/versions, never executes the installed browser or
fetches a feed, and remains active with `--offline` and `--no-arch-audit`. Entries need an exact Arch package mapping, a verified
Linux upstream fixed floor, authoritative exploitation evidence, references,
and a review date. The initial comparator supports only canonical four-part
numeric Chromium releases; adding other products requires explicit review of
their version semantics and finding descriptions. The curated baseline ships
in `aurascan/assets/runtime-intelligence.json`; separately signed updates can
replace its reviewed records only after production trust is provisioned.
Normal audits never fetch or reload intelligence within an operation.

On 2026-09-11 the [Google release announcement](https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop_0808145027.html)
and [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
confirmed CVE-2026-87491 exploitation and the Linux floor `153.0.8010.36`.
Arch's [package metadata](https://archlinux.org/packages/extra/x86_64/chromium/json/)
reported `152.0.7977.82-1`; the [Arch tracker](https://security.archlinux.org/package/chromium)
did not yet list this CVE. Those are dated observations, not runtime checks.
The [Chrome CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-87491)
describes versions prior to the floor, but its structured `version` and
`lessThan` values both equal that floor. The curated exclusive upper bound
uses the vendor announcement and CNA prose; no introduced lower bound is
established. Do not mechanically import the inconsistent structured interval.
Google rates the issue Medium; AuraScan's HIGH prioritization reflects the
confirmed exploitation evidence, not an attributed Google severity rating.

Keep `SEC-KNOWN-EXPLOITED-VERSION-LAG` separate from distribution-feed findings
and malware incidents. Supported versions at/above the floor mean only that
this advisory did not match. Unknown/missing versions require
`SEC-VENDOR-ADVISORY-VERSION-UNRESOLVED` and partial coverage without echoing
untrusted version text. Package-query failures must also keep coverage partial.
Epoch/pkgrel cannot override an upstream range, and package names/versions
cannot establish official origin, signatures, backports, or exploitation.
Do not discount findings based on repository presence, out-of-date flags,
signatures, or a currently empty `arch-audit` result.

The upgrade consumer may suppress this HIGH warning only for a supported,
exact mapped repository candidate reaching the floor, preserving the original
audit evidence. An AUR candidate, epoch-only bump, custom version, or unrelated
update cannot do so. Upgrade snapshots currently collect package names only;
without captured versions this check remains unresolved coverage. Adding
version collection there is deferred. Full system audit collects versions.

Security audits are regenerated, not package-scan cache entries. The report
remains schema 1.0 with additive intelligence identity metadata,
`risk_summary.vendor_emergency_findings`, and captured advisory identity/floor
on findings. Tests use injected package maps, temporary roots, and fake
runners; no browser, package payload, real host scan, or live feed is needed.

### npm campaign intelligence and lifecycle correlations

Keep the runtime baseline in `aurascan/assets/runtime-intelligence.json` and
pass its captured snapshot to matchers. The retained historical
`aurascan/assets/npm-shai-hulud-2026-09-07.json` records the original evidence;
the supporting Aikido, GHSA, and OSV references were checked on 2026-09-09.
The four exact observed releases
and common payload hash are narrower evidence than the GHSA package-wide
malware ranges. Exact tuples block; for those explicitly broader advisories,
unresolved or other versions remain HIGH review and must never be presented as
patched or safe. Exact-only future records cannot inherit that broader claim.
OSV record-origin hashes
are not payload hashes: use only the identified `index.js` evidence digest.

`aurascan/analyzers/npm_supply_chain.py` consumes supported shell install
arguments, package manifest identities/dependency selectors, and npm lockfile
v1/v2/v3 or shrinkwrap records. Decode aliases to their real package identity,
keep option arguments and quoted messages out of dependency selections, and
never resolve an unpinned selector by running a package manager or contacting a
registry. Command matching supports literal selectors and destinations; opaque
dependency variables require coverage review, and shell-variable C2 destinations
are not resolved. Match C2 against the actual parsed network hostname, not a substring,
userinfo, URL path, or output filename. Keep fixed explanations and advisory
IDs secret-free; never persist lifecycle command text.

Deep-static hashes every bounded regular acquired source file, including
non-code assets and archive-supplied `.git` files, without following links or
interpreting payloads. VCS internals receive hash and archive-prefix checks only.
Code/text and vendored dependency candidates retain the 1 MiB content limit;
other non-code hashes stream in 64 KiB
chunks with a 64 MiB per-file ceiling. The content-read allowance is 256 MiB per
tree, including shebang selection reads, with at most 20,000 traversed entries
and 5,000 regular-file candidates. Exhausted
bounds and unsafe, replaced, unreadable, or unsupported inputs remain coverage
blockers. A bounded 512-byte prefix identifies supported archive/compression
magic even after renaming. Known archive suffixes and supported magic require
separate inspection; unexpanded contents and unrecognized formats cannot be
reported as inspected.

`aurascan/analyzers/npm_lifecycle.py` accepts captured text only. Bind exact
supported preinstall/install/postinstall/prepare Bun/Node launchers to the
same package's root `index.js`. Retain at most 8 MiB of manifest/entry text
across one tree for this correlation. Do not read another package's entry file
or an escaped path to fill missing evidence. Distinguish active credential
access, configuration writes, network targets, and publication operations from
comments, strings, names, and unreachable helpers. The lexical subset is not a
JavaScript evaluator; arbitrary imports, computed calls, callbacks, obfuscation,
and dynamic data flow are not comprehensively followed. Parser limits or a
missing required supported entry are coverage findings, not malware claims.

Use the inert `source_shai_hulud_lifecycle` archive template and temporary roots.
Its fake credential paths, example.invalid endpoint, and empty configuration
writes are never executed. Hash regressions inject an inert byte digest rather
than shipping the malware. Tests must also cover renamed non-code files,
replacement and symlink refusal, budgets, benign lifecycle/configuration use,
wrong-package correlations, and secret-free findings. Full/smart engine tests
must preserve the blocker despite an accepted baseline or favorable source
metadata. The explicitly weaker `new-only` update policy still skips update
content scans; explicit deep-static overrides that skip. No registry-reputation
allow path exists or is introduced.

### Precompiled Python source carriers

`aurascan/analyzers/python_bytecode.py` classifies bounded header bytes and
`.pyc`/`.pyo`/`.pyd` candidates. Repository discovery now includes `__pycache__`
under its existing traversal/byte limits; VCS, other named cache/dependency,
declared-source, and generated-root exclusions still apply. Names select
candidates, while recognized magic and complete headers determine bytecode
classification. Only a recognized PEP 552 header with flags exactly `1`
establishes unchecked-hash mode; do not interpret legacy timestamp words or
unknown/truncated headers as those flags. `.pyd` names alone indicate native
extension candidates, not PEP 552 metadata.

Presence is MEDIUM/manual and unchecked-hash mode HIGH/manual, both without a
hard block. Existing exact repository install/execution tiers remain in force.
Acquired shell-script execution uses a bounded correlation helper and requires
an exact captured path; script location alone never proves runtime cwd, and a
matching unresolved reference produces incomplete coverage. This helper is
limited to supported `.sh`, `.bash`, and `.zsh` streams, not Make recipes or
Python import resolution. No header authenticates the code body or proves a
source mismatch. Tests use header-plus-inert-sentinel bytes, never marshaled
code objects or imports, and cover source/header coexistence, modes, bounds,
path mismatch, comments/messages, and secret-free output.

Package rules advance to `1.6.0` and repository snapshot identity to `1.1` so
old allow results cannot conceal these changed inspection semantics.

### Remote second-stage execution

`SUPPLYCHAIN-REMOTE-STAGE-EXEC-001` is a deterministic correlation for
PKGBUILD and declared install-hook text. Require a command-position network
download or Git clone, a concrete local artifact identity, and later execution
of that artifact or a bounded decoded/copied derivative. Keep source arrays,
comments, quoted documentation, downloads that are only packaged, path
mismatches, and every incomplete correlation negative. Emit only fixed behavior
labels; URLs, paths, tokens, and model prose do not belong in evidence.

The shared command parser is bounded. A parser limit, malformed command stream,
or other incomplete correlation pass must produce blocking
`STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001`; incomplete inspection is not a
malware claim. `SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001` reuses the same parser and
requires either a local decode-to-artifact followed by execution of that exact
artifact, or active invocation of a media-, document-, data-, or font-suffixed
path as code. Never flag an asset name, source/archive declaration, local file,
decode step, comment, message, or quoted example by itself.

The acquired-source variant, `DEEPSTATIC-REMOTE-STAGE-EXEC-001`, applies the
same narrow data-flow correlation to bounded interesting source text. It does
not render images or treat a picture/media filename as malicious by itself.
Tests may represent a carrier with inert bytes and `example.invalid`, but must
never decode or execute fixture content. The acquired-source local-carrier
variant is `DEEPSTATIC-OPAQUE-CARRIER-EXEC-001`; an incomplete parser or source
tree must keep `DEEPSTATIC-INSPECTION-INCOMPLETE-001` blocking.

Built package `.INSTALL` members are mandatory deterministic evidence. Capture
them through the bounded no-follow archive reader, reject invalid/binary or
unstable content, and fail closed with
`PACKAGE-INSTALL-HOOK-UNINSPECTED-001`. Resolve `.PKGINFO` identity through the
same reader: execute only an already-opened trusted `/usr/bin/bsdtar`, bind its
identity before and after use, bound stdout, and reject links, replacement,
duplicate identity fields, and invalid text without printing or persisting
archive bytes or tool diagnostics.
Do not rely on optional AI or ClamAV to cover privileged install-hook control
flow. Keep built-package cache reads and writes disabled until identity,
analyzers, and the cache key all consume one immutable no-follow archive
snapshot.

Deep-static source discovery must parse the exact captured PKGBUILD bytes, not
an independently mutable sibling `.SRCINFO`. Local sources are copied through
bounded no-follow component walks into per-reference private paths. Offline
mode performs no HTTP, Git, or key fetch, and any declared source that cannot be
inspected blocks the deep-static result. Do not read or write a deep-static
cache entry until the cache identity includes immutable acquired-source bytes
or revisions and every acquisition status. Reject source/key URLs with
userinfo, localhost, or non-public IP literals before the initial request and
after redirects; strip userinfo, query strings, and fragments from persisted
URL metadata. Document that this lexical boundary does not eliminate DNS
rebinding rather than claiming a complete network sandbox.

Treat source-array parsing as a refusal boundary, not a Bash evaluator. Support
only bounded literal assignments/appends and simple constant interpolation.
Malformed arrays, dynamic expansion, subscripts, indirect assignment,
`eval`/sourcing, reads into source variables, and `declare`/`typeset` namerefs
that could alias a source array must return blocking
`SOURCE-PARSER-AMBIGUOUS`. Tests should include indentation, trailing comments,
quoted closing parentheses, appends, malformed input, and unrelated inert
source-looking strings.

Explicit Git and signature workflows may invoke native tools on hostile data,
so capture and revalidate only `/usr/bin/git` and `/usr/bin/gpg`; never validate
one path and later execute a bare name. Git runs with isolated HOME/config,
credentials and hooks disabled, bounded time and combined child output, and no
recursive submodules. GPG uses the same bounded child-output runner and retains
only allowlisted machine status names plus hexadecimal key identifiers.
Public-key cache state must use a private user-owned final directory, bounded
stable no-follow key reads, and atomic private no-replace publication. Copy the
exact captured key bytes into the private temporary GPG home before import so a
configured or cached key path cannot be swapped between review and use. These
controls reduce replacement risk but do not sandbox Git/GPG parsers or remove
the need to isolate explicit acquisition.

Stream archive and source-tree enumeration under explicit entry, candidate,
file-size, and actual extracted-byte limits. Bind archive inputs and candidate
files to no-follow regular-file snapshots, fail closed on replacement or
incomplete reads, and remove partial extraction output transactionally. Do not
silently skip archive links or treat attacker-declared member sizes as the
extraction budget. Until recursive nested-archive inspection carries the same
budgets and depth accounting, detect nested archives in the acquired tree and
block them as incomplete inspection.

Config-drift, incident, and recovery AI prose is data too. Parse bounded JSON
with duplicate-key rejection, require exact schemas and known local IDs, and
accept only short single-line advisory prose after compatibility normalization.
Reject recognized scheme, bare, IP, email, and obfuscated destinations; direct,
actor/modal, recommendation, and sentence-leading imperative instructions;
named or generic package-manager/install-helper advice; actionable nominalized
operation/invocation forms; credential-transfer instructions; questions;
commands; terminal controls; product impersonation; credential-like
assignments; and unsupported safe/compromised claims. Keep benign declarative
uncertainty and evidence statements such as “may indicate” or “an invocation
was observed” usable when they do not direct an action. Persist a fixed
secret-free rejection reason, never the rejected raw provider response or
exception.

Validated model prose is still untrusted interpretation, not allowlisted
program semantics. The lexical guard cannot prove every natural-language
construction inert, so prose must never acquire tools, URL fetching, command
execution, policy authority, or the ability to invent an ID. Prefer fixed
templates and allowlisted semantic labels over adding another free-form model
field. Add central `text_safety` positives and adversarial negatives whenever
the shared prose contract changes.

## Smart update context contract

The smart update fast path is conservative. The default scan context is
`unknown`, which falls back to the normal scan. `--deep-static` overrides
fast-path source-scan skipping.

Context providers must prove update context before AuraScan may use smart
update behavior. A provider must know package identity, installed package
state, installed version or confirmed absence, candidate version, and the
transaction operation. Provider errors, missing local package database
information, ambiguous split-package mapping, or incomplete transaction data
must fall back to unknown/not eligible.

`--scan-context auto` is an opt-in local context check. It reads the local
pacman package database from `/var/lib/pacman/local` without root, sudo,
network access, package installation, makepkg, or package/source-code
execution. If the local database proves that the candidate PKGBUILD represents
a newer version of an already installed package, AuraScan marks the context as
`update` with `verified_local_package_db` authority. If it proves the package
is absent, AuraScan treats the scan as an install and uses the normal scan. If
package identity, installed state, candidate version, version comparison, or
local database parsing is incomplete, AuraScan returns `unknown` and uses the
normal scan.

The local database provider uses Arch `vercmp` when available. If version
comparison is unavailable or errors, it does not guess from version strings and
does not enable a fast path.

Split packages are intentionally limited. A single clear `pkgname` can be
classified. A split package can be treated as an update only when every
produced package name is parsed safely, `pkgbase` is explicit, all produced
packages are installed, and all installed versions compare older than the
candidate version. Partial installs, missing `pkgbase`, duplicate or dynamic
package names, mixed version states, and pkgbase-only inference return
`unknown`.

Future pacman hook providers must use reliable transaction information and
distinguish installs from upgrades when possible. The current
`aurascan-makepkg` command uses the local database `auto` context path; a future
provider that explicitly reports `ScanContextSource.makepkg_wrapper` must follow
the same proof contract and return unknown when split packages or local package
database queries are ambiguous.

The following are not proof of update context:

```text
package name alone
dependency list stability
"no new dependencies"
version string alone
AUR metadata alone
user intent without explicit user-asserted opt-in
```

Manual `--scan-context update` is user-asserted, not provider-verified. It is
for controlled integrations and advanced testing. It can participate in smart
or new-only update decisions only when paired with
`--allow-user-asserted-update-context`, and reports must label that context as
user asserted. This is different from `--scan-context auto`, which can produce
verified local database authority only when local evidence is complete. Skipped
`new-only` updates must not become trusted baselines.

## upgrade preflight

`aurascan upgrade` is an upgrade-risk advisor and package-manager front door,
not a package malware scan and not a guarantee that an upgrade will work. Keep
it separate from `AuraScanEngine` and the pacman archive hook: the hook remains
a last-minute package archive scanner, while upgrade preflight reasons about
transaction and local system breakage risk.

The default handoff is `/usr/bin/sudo /usr/bin/pacman -Syu`. Helper use is
limited to update queries: `paru -Qua`, `yay -Qua`, and the version-matched
Shelly AUR JSON query. Repo package previews should come from pacman's `--print
--print-format` path. If a helper query finds no AUR build, the final command
must be repository-only pacman rather than a fresh helper transaction that
could expand after preflight. If it finds any planned AUR build, emit blocking
`UPG-AUR-BUILD-UNSCANNED`; do not invoke the helper unless a future design can
prove a real per-package `aurascan-makepkg` integration. Do not simulate that
proof with a flag or environment marker. Preflight must not run makepkg, build
AUR packages, inspect AUR sources, or execute package code.

Capture `/usr/bin/sudo`, `/usr/bin/pacman`, and the absolute path returned for a
selected helper as executable identities. Reject final files or path components
that are symlinks, not root-owned, or group/world writable; reject non-regular
or non-executable final files. Revalidate device, inode, owner, group, and mode
immediately before every preview/query and final handoff. Tests must cover a
hostile `PATH`, symlinks, and replacement after preview. Never fall back to a
bare command name after a trust check fails.

Upgrade preflight is enabled by default. The wizard may write
`AURASCAN_UPGRADE_PREFLIGHT_ENABLED`, `AURASCAN_UPGRADE_AUR_HELPER`,
`AURASCAN_UPGRADE_PREFLIGHT_AI`, and
`AURASCAN_KERNEL_MODULE_AUTOPILOT_ENABLED` to user config. If preflight is
disabled, `aurascan upgrade` must not silently run a raw package-manager
upgrade; it should report that preflight did not run and exit without invoking
pacman or a helper. `--enable-preflight` may override a disabled config for one
invocation.

Kernel/module autopilot is deterministic and enabled by default. It may verify
kernel families, running-kernel mapping, headers, DKMS status, prebuilt module
package pairing, fallback kernel evidence, and reboot need. It may prepare
bounded repo-package fixes, but must ask before running any extra package
command; `--yes` must not silently apply those fixes. After a successful
package-manager handoff, autopilot should run post-upgrade aftercare and report
module/reboot status without rebooting automatically.

Most preflight findings are advisory. HIGH or CRITICAL breakage risk requires
AuraScan's extra confirmation prompt unless `--yes` is used. Deterministic
security invariants may be hard blockers: in particular,
`UPG-AUR-BUILD-UNSCANNED` cannot be cleared by confirmation, `--yes`, or AI.
For an allowed repository-only transaction, pacman still owns its normal
confirmation and failure behavior.

AI upgrade review is raise-only. It may raise an existing deterministic rule ID
up to HIGH, but it cannot create a standalone finding or action, lower or
suppress a deterministic finding, change blocking policy, or mark an upgrade
safe. Require an exact bounded JSON schema, at most twelve unique raises,
allowlisted severities, and short safe prose; reject duplicate keys, extra
fields, unknown IDs, URLs, commands, controls, credential-like assignments,
and unsupported safety/compromise claims without retaining raw output. The
prompt uses only a redacted structured summary of package names, versions,
deterministic findings, and selected local system facts. Do not send
environment variables, API keys, arbitrary command output, or file contents.
Deterministic autopilot owns package-fix decisions and local verification
status.

## config drift assistant

`aurascan config-drift` handles `.pacnew` and `.pacsave` maintenance as a
system-maintenance helper, not as a package security scan. It should stay
usable as a standalone command and as part of `aurascan upgrade`.

The assistant is enabled by default when upgrade preflight is enabled. The
wizard may write `AURASCAN_CONFIG_DRIFT_ENABLED` and
`AURASCAN_CONFIG_DRIFT_AI_DIFFS`. AI diff policy values are `ask`, `never`, and
`always`; the default is `ask`, which means no configured AI provider receives config diffs
unless the user opts in for that run.

Config drift applies must be backup-first. Before any write or `.pacnew`
removal, copy the target and drift file to
`/var/lib/aurascan/config-drift/<run-id>/` or the test-provided backup root and
write a manifest with paths, action, ownership/mode where available, and
checksums. Remove `.pacnew` only after the target write succeeds. `.pacsave`
auto-restore/delete is out of scope for v1.

Deterministic local planning owns authority. AI may add explanations, but it
must not bypass backups, path sensitivity classification, validators, or
confirmation behavior. Sensitive paths include package-manager config,
bootloader/initramfs config, sudo/PAM, networking, users/groups, SSH, systemd,
and security policy. Nontrivial sensitive merges should remain manual unless a
future deterministic merge validator can prove the exact candidate.

AI-provider config-diff prompts must use bounded redacted diffs only. Redact
secrets, tokens, keys, passwords, private-key blocks, credential URLs, and
similar auth material before request construction. Invalid AI JSON is
non-blocking and must not change planned actions.

## Policy-Gated Repair Agent command boundary

The foreground Policy-Gated Repair Agent is the one AI workflow whose explicit
command-enabled access profiles can accept a command field. Keep `guarded`
command-free. The `user-shell` and `root-shell` names remain configuration/API
compatibility values; neither grants a general shell. Validate one exact bounded
response schema and reject unknown fields, unsafe advisory prose, fabricated
IDs, and commands whose hash-derived identifier does not match their content.
Every exact model-authored command is then displayed and confirmed
independently; legacy `whole-plan` and `session` settings normalize to effective
`each-command` authorization.

Commands are a fail-closed local allowlist. Permit only the small documented set
of shell output/test builtins, absolute `/usr/bin` or `/usr/sbin` read-only
diagnostics with command-specific mutation/escape checks, and constrained exact
`/usr/bin/pacman` query, sync, or removal workflows. Reject every non-allowlisted
program plus remote references, network/remote-shell clients, Git, AUR helpers,
source/build front ends, interpreters, decoding/evaluation, shell expansion,
redirection, and unsafe package-manager options. Pacman must reject `-U`,
alternate root/config/keyring/hook paths, unsafe operation combinations, path
targets, and direct modification of AuraScan. Capture and revalidate the
package-managed `/usr/bin/sudo` and `/usr/bin/aurascan` identities before every
privileged broker call.

Add positives for hostile prompt-injected commands, PATH-shadowed/bare/custom
executables, mutating diagnostic flags, and pacman bypass attempts. Add
negatives only for inert prose, allowed builtins, exact absolute diagnostics,
and constrained pacman operations. Root package repair remains consequential,
and diagnostic output may contain private data; the allowlist is not proof that
every permitted argument or package transaction is harmless. Do not describe
this feature as Full Control, unrestricted shell, arbitrary commands, or remote
code execution.

## makepkg wrapper

`aurascan-makepkg` is a makepkg-side front door for AUR workflows:

```bash
aurascan-makepkg --syncdeps
aurascan-makepkg --aurascan-deep-static --syncdeps
aurascan-makepkg --aurascan-offline --aurascan-no-auto-key-fetch --syncdeps
aurascan-makepkg --aurascan-update-scan-policy smart --syncdeps
```

The wrapper looks for `PKGBUILD` in the current directory, runs AuraScan first,
and invokes the real `makepkg` with the original makepkg arguments only when
AuraScan allows the build. AuraScan-only flags use the `--aurascan-*` prefix and
are not passed to makepkg.

After scanning, capture only `/usr/bin/makepkg` through the shared trusted-tool
boundary and revalidate its exact device/inode, ownership, group, and mode
immediately before invocation. The final file and path components must be
root-owned, non-writable, regular/executable where applicable, and non-link.
Hostile PATH resolution, a different installation, or replacement after the
scan fails closed; never fall back to a bare `makepkg` name.

The wrapper protects the pre-build phase: it scans the PKGBUILD before
`prepare()`, `build()`, `check()`, `package()`, or package/source-tree helper
scripts can run. It also statically scans a declared local `install=` script
when one is present. It does not sandbox makepkg, execute package functions,
install packages, fetch live AUR data, or make a package safe by itself.

A literal local `install=` declaration is a fail-closed evidence dependency.
Resolve and read it before returning an allow result, even when its basename is
dot-prefixed. Missing, unreadable, unsafe, ambiguous, or any symlinked component
of the declared relative hook path under the package directory blocks before
makepkg. Include the resolved hook or its bounded failure-state identity in
cache and review fingerprints: blocker reports may be cached for the same
failure state, but an unresolved hook must never reuse or store an allow
decision.

If AuraScan blocks, `aurascan-makepkg` does not invoke makepkg. If AuraScan
requires manual review, the wrapper also stops before makepkg by default. This
is intentional: PKGBUILD build steps can execute commands during package
creation, so suspicious-but-not-confirmed findings require a deliberate review
decision before makepkg runs.

Manual review acceptance is not a generic force flag. When only eligible
manual-review findings are present, the wrapper prints a review token for the
exact scan. To continue after reviewing the findings, rerun with the original
makepkg arguments and the token:

```bash
aurascan-makepkg --aurascan-accept-review arv-... --syncdeps
aurascan-makepkg --aurascan-accept-review arv-... --aurascan-review-reason "reviewed upstream key issue" --syncdeps
```

By default, review acceptance is one-time. `--aurascan-remember-review` records
a persistent decision, but it is still scoped to the same exact scan
fingerprint. `--aurascan-review-once` forces one-time behavior.
`--aurascan-review-expire-days <N>` can attach an expiry time to the recorded
decision; expired decisions cannot be reused. Tests and controlled runs can use
`--aurascan-review-db <path>` to keep review decisions out of the real user
database. The normal store is:

```text
~/.local/share/aurascan/review_decisions.db
```

Review tokens are not treated as secrets. They are deterministic handles for a
specific scan fingerprint, but the review database is still local audit data.
AuraScan creates the review DB file with restrictive permissions where the
platform allows it.

The token becomes invalid if the PKGBUILD changes, a declared local `install=`
hook changes, the source metadata signal changes, the package version changes
as part of the exact scan, the manual-review finding set changes, the scan
configuration changes, or scanner/rule versions change. New blockers or new
manual-review findings require a new review.

Local review decisions can be listed without scanning or invoking makepkg:

```bash
aurascan-makepkg --aurascan-list-review-decisions
aurascan-makepkg --aurascan-list-review-decisions --aurascan-review-package demo
aurascan-makepkg --aurascan-list-review-decisions --aurascan-review-status used
aurascan-makepkg --aurascan-json --aurascan-list-review-decisions
```

Review decisions can be revoked without deleting their audit trail:

```bash
aurascan-makepkg --aurascan-revoke-review <decision_id>
aurascan-makepkg --aurascan-json --aurascan-revoke-review <decision_id>
```

Revoking a decision prevents future reuse. It does not undo a package build
that has already happened. Pruning old decisions is not implemented yet; prefer
revocation for now when a decision should no longer be trusted.

Ordinary review acceptance cannot bypass hard blockers. Confirmed malware
signatures, checksum mismatches, invalid signatures, signer fingerprint
mismatches, unsafe archive extraction, deterministic CRITICAL findings, and any
finding already marked as blocking remain stops for this workflow. If review
decision storage is unavailable, acceptance fails closed and makepkg is not
invoked.

Accepted manual review is stored distinctly as `manual_review_accepted`. It may
allow the current makepkg invocation to proceed, but it is not a clean trusted
baseline and must not enable the smart update fast path. Unresolved
manual-review scans, blocked scans, and `new-only` skipped updates also do not
update trusted baselines.

When `--aurascan-json` is used through the wrapper, stdout contains one
wrapper-level JSON object. The envelope includes the wrapper action, makepkg
invocation status, wrapper exit code, stripped AuraScan-only arguments, review
fields, and the underlying scan report when a scan was run. Management commands
such as list and revoke also use the same envelope and do not require a
PKGBUILD.

Example actions include:

```text
manual_review_required
review_accepted
scan_blocked
makepkg_invoked
makepkg_failed
review_listed
review_revoked
error
```

The wrapper defaults to `--scan-context auto` behavior using the local package
database provider. If local DB proof is incomplete, split-package mapping is
ambiguous, version comparison is unavailable, or the package is not installed,
the scan falls back to normal conservative behavior. Smart fast path behavior
still requires verified update context, an accepted baseline, trust-diff
approval, and no `--aurascan-deep-static` override. No-new-dependencies is never
enough to skip scanning.

The release-safe pacman hook template is `packaging/arch/aurascan.hook`. The
root `aurascan.hook` mirrors that release-safe hook. It calls `/usr/bin/aurascan`
and must not contain source-checkout paths, virtualenv paths, or developer home
directories. Development-only hook experiments belong under `contrib/dev/` and
must be clearly marked as development-only.

The pacman hook is different from the wrapper. It is a pacman PreTransaction
hook that scans built package archives before the pacman transaction. That can
help with package archive/install metadata, but it is too late to protect
against malicious PKGBUILD build-time logic that may run while makepkg is
creating the package. The pacman hook remains conservative and does not
currently provide a verified transaction context provider for smart fast path
decisions.

`pip install` does not install pacman hooks. Release packages should install
the hook as a package file, normally to `/usr/share/libalpm/hooks/aurascan.hook`.
Manual local hooks live under `/etc/pacman.d/hooks/`, but users should remove
manual hooks before uninstalling AuraScan. A hook pointing to a missing
executable can break pacman transactions.

Current hook failure behavior is intentionally simple: missing archive targets
are warnings and do not block by themselves; blocking findings return non-zero
and should stop the pacman transaction. ClamAV runs only through captured and
revalidated `/usr/bin/clamscan`, with symlink following, scan bytes, file count,
recursion, and runtime bounded; database version checks likewise require
trusted `/usr/bin/freshclam`. Use a fixed minimal environment, terminate option
parsing before the caller-controlled target path, suppress clean-file output,
and bound combined child output. Do not persist raw ClamAV stdout/stderr, and
keep signature/path evidence terminal-safe and secret-free. A started scan that
times out, exceeds a bound, or exits with an error is blocking incomplete
inspection. A missing or unsafe `clamscan` skips AV with a warning. A missing
`/usr/bin/aurascan` executable is
a hook installation problem that users recover from by reinstalling AuraScan or
removing the stale hook.

Future AUR-helper integration should prefer configuring the helper's makepkg
command, when supported, to call `aurascan-makepkg`. Future pacman hook context
providers must prove transaction operation, installed state, package identity,
and version information before they can participate in smart update decisions.

## CodeWhale advisory and Git argument boundaries

Installed-version exposure uses only captured exact package names and bounded
Arch version metadata. The verified CodeWhale/codewhale-tui range is
`>=0.8.41,<0.8.64`; documented `codewhale-bin` and legacy `deepseek-tui-bin`
aliases are explicit. Preserve each legacy advisory lower bound and mark the
ambiguous `0.8.41` rename/ecosystem boundary unresolved. Never turn a version
match into a campaign, malicious-package, exploitation or current-AUR claim.
All advisory transports and installed-agent execution remain unnecessary.

Source Git branch/tag fragments are URL-decoded before transport and must not
start with `-`. Reject option-shaped values before clone or checkout; separate
argv elements do not prevent Git option interpretation, and checkout's `--`
selects paths rather than revisions. Test through an intercepted trusted
runner with inert paths. Package rule version `1.6.1` invalidates older cached
decisions; this shared acquisition-boundary change requires a recovery-bearing
future release.
