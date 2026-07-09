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
python -m compileall aurascan tests
```

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

Wizard-created configs must set `AURASCAN_AI_ENABLED` explicitly. Local-only
setup writes `AURASCAN_AI_ENABLED=0`. Network AI setup may write
`AURASCAN_AI_PROVIDER`, `AURASCAN_AI_MODEL`, and one provider-specific key such
as `AURASCAN_OPENAI_API_KEY`. Legacy `AURASCAN_AI_KEY` remains supported so
existing users do not lose behavior.

When AuraScan runs as root from a sudo-launched pacman hook, config loading may
also read the invoking user's `~/.config/aurascan/.env` from `SUDO_USER`.
Unattended or direct-root hook contexts should use `/etc/aurascan/.env`.

`aurascan doctor` is diagnostic. It must not contact AI providers unless
`--check-ai` is supplied, and it must never print secret values. Missing
optional tools should be warnings unless the checked workflow cannot proceed.
Doctor should report upgrade preflight and config drift assistant config state,
including invalid env values, without reading or printing config file contents.

Manual hook setup from `aurascan init` is allowed only for the local admin hook
path `/etc/pacman.d/hooks/aurascan.hook`. The installer must refuse hook writes
unless `/usr/bin/aurascan` exists and the template is release-safe. Packaged
installers should still own `/usr/share/libalpm/hooks/aurascan.hook`.

Package install scripts must stay non-interactive. They may print advisory
first-use guidance, but they must not run `aurascan init`, run `aurascan
doctor`, request secrets, write user config, install local `/etc` hooks, run
makepkg, inspect packages, or contact the network during install or upgrade.

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
cron file installation, crontab command use, cron `@reboot` entries, and
deep-static systemd unit/auto-enable/user-persistence split behavior.

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
to `paru -Syu`, `yay -Syu`, and
`shelly upgrade-all --no-flatpak --no-appimage`; generic helper commands are out
of scope until they can be validated safely. Repo package previews should come
from pacman's `--print --print-format` path. AUR update context may come from
helper `-Qua` or Shelly's `check-updates --aur --json`, but v1 must not run
makepkg, build AUR packages, inspect AUR sources, or execute package code during
preflight.

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
`always`; the default is `ask`, which means no network AI receives config diffs
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

Network AI config-diff prompts must use bounded redacted diffs only. Redact
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
