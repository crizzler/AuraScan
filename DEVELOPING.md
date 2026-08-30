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
bypass environment proxies; refuse HTTP redirects; use bounded response reads
and timeouts; and never fall back to a cloud endpoint. Do not start a server,
download a model, enable tools or MCP, or send a live request from tests. Use
injected openers and assert that credentials do not appear in diagnostics,
exceptions, or serialized details.

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
semantic behavior labels, and a fixed reason, but no source snippet. Correlated
multi-line behavior must identify the contributing ranges; file-level
integrity, read, or parser findings must explicitly omit a precise location
when one cannot be established safely. The terminal renderer prioritizes
suspicious files, prints the deterministic reason and locations, and separates
them from integrity-only inventory. A truncated page must be labeled as
incomplete and explain that its committed continuation remains pending.

Keep content risk distinct from integrity state. Suspicious first-seen files
alert immediately; otherwise clean first-seen recognized files form one
unreviewed inventory. Render that state as an integrity-only approval request,
not as a suspicious-content finding; AI remains `not-needed` when the clean
first-seen file has no deterministic content finding. Store SHA-256 plus
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
approves content.

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
scripts, and deep-static systemd
unit/auto-enable/user-persistence split behavior.

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

The default handoff is `sudo pacman -Syu`. Supported helper execution is limited
to `paru -Syu`, `yay -Syu`, and Shelly's scoped upgrade command. Shelly 3 uses
`shelly upgrade all --no-flatpak --no-appimage` and
`shelly list-updates aur --json`; AuraScan keeps the corresponding
`upgrade-all` and `check-updates --aur --json` forms for Shelly 2. Generic
helper commands are out of scope until they can be validated safely. Repo
package previews should come from pacman's `--print --print-format` path. AUR
update context may come from helper `-Qua` or the version-matched Shelly query,
but v1 must not run makepkg, build AUR packages, inspect AUR sources, or execute
package code during preflight.

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

Preflight findings are advisory. HIGH or CRITICAL risk requires AuraScan's
extra confirmation prompt unless `--yes` is used, but this is not a hard-blocker
system. If the user continues, pacman or the helper still owns the actual
transaction and its normal confirmation/failure behavior.

AI upgrade review is raise-only. It may add `UPG-AI-RISK` or raise an existing
preflight finding up to HIGH, but it must not lower deterministic findings,
mark an upgrade safe, suppress findings, or hard-block by itself. The prompt
must use a redacted structured summary only: package names, versions,
deterministic finding summaries, and selected local system facts. Do not send
environment variables, API keys, arbitrary command output, or file contents.
AI may explain or raise kernel/module risk, but deterministic autopilot owns
package-fix decisions and local verification status.

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

The wrapper protects the pre-build phase: it scans the PKGBUILD before
`prepare()`, `build()`, `check()`, `package()`, or package/source-tree helper
scripts can run. It also statically scans a declared local `install=` script
when one is present. It does not sandbox makepkg, execute package functions,
install packages, fetch live AUR data, or make a package safe by itself.

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
and should stop the pacman transaction; missing `clamscan` skips AV with a
warning; a missing `/usr/bin/aurascan` executable is a hook installation problem
that users recover from by reinstalling AuraScan or removing the stale hook.

Future AUR-helper integration should prefer configuring the helper's makepkg
command, when supported, to call `aurascan-makepkg`. Future pacman hook context
providers must prove transaction operation, installed state, package identity,
and version information before they can participate in smart update decisions.
