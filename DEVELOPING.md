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
are mocked; CI explicitly disables general and Instruction Guard AI and never
starts a live local model server.

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

Keep suspicious-content risk, integrity approval, and coverage limitations as
three separate presentation concepts. `review_required` may be true because of
any one of them and must not be rendered as if it always means malware was
detected. The terminal renderer should lead with their separate counts, avoid
presenting the report's fallback LOW value as a suspicious-content severity
when there is no content finding, and group suspicious instructions ahead of
changed/unsafe files, clean first-seen inventory, and coverage limitations.
Wrap prose and long paths predictably for narrow terminals without corrupting
IDs, line ranges, or JSON output. A truncated page must be labeled as incomplete
and explain that its committed continuation remains pending.

Suspicious first-seen files alert immediately; otherwise clean first-seen
recognized files form one unreviewed inventory. Render that state as an
integrity-only approval request and explicitly say that first-seen means no
machine-bound approval exists, not that suspicious content or malware was
found. AI remains `not-needed` when a clean first-seen file has no eligible
deterministic content finding. For eligible findings, place a fixed
deterministic explanation beside its exact evidence roles and show only an
evidence-mapped AI rationale labeled as advisory. AI prose cannot replace the
deterministic explanation, create or move a location, establish trust, or enter
the integrity-only inventory. Disclose how many displayed findings received a
bounded AI explanation, and label malformed or incompletely parsed
configuration as scan coverage rather than suspicious content. Give safely
approvable new or changed files a concrete next step; unsafe identities must
remain manual-only. Store SHA-256 plus
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

Desktop notifications and tray/public alert state are secret-free: retain only
generic severity/count/review wording, never paths, snippets, usernames,
credentials, or AI output. Deduplicate by candidate identity, content hash, and
rule set. Acknowledgment suppresses duplicate notification only and never
approves content. Resolve notifications through the shared trusted-tool
boundary: only captured and revalidated `/usr/bin/notify-send` may run. Its
absence is a notification-delivery limitation, not a reason to discard private
CLI/tray review state.

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
approval invalidation, corrupt state, alert deduplication, and exact
disable/restore refusal and round trips. Mock AI, systemd, tray, and
notifications; tests must not scan a real home, start a model, contact a
provider, require root, or invoke live systemd.

Presentation tests must cover inventory-only, suspicious-only, mixed, changed,
coverage-limited, continuation, and legacy reports. Assert that clean first-seen
files are never labeled as suspicious; contributing ranges retain their exact
one-based locations and per-range roles; deterministic and advisory AI reasons
remain distinct; narrow-terminal wrapping preserves IDs and meaning; `--json`
remains schema-stable and unwrapped; and source snippets, credentials, URLs,
terminal controls, and rejected or unmapped AI prose never enter review output.

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
