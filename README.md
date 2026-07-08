# AuraScan

AuraScan is a security-focused package scanner for Arch, CachyOS, and AUR
workflows. It is designed to catch the vast majority of obvious and moderately
sophisticated malicious package behavior and to reduce risk during package
installation.

AuraScan does not prove that a package is safe. A clean report, a clean ClamAV
result, or a valid source signature is not a guarantee. The goal is to find risk
signals early, explain them clearly, and stop dangerous flows before package
code runs.

A clean ClamAV result is not proof of safety. A valid source signature is not a
guarantee that the package behavior is safe.

## Status

AuraScan is a developer preview. It is ready for early testing and review, but
its packaging, rule set, and integration story should still be treated as
pre-1.0.

## Quickstart

For a development checkout, install AuraScan and launch the setup wizard with
one shell command:

```bash
python -m pip install -e ".[test]" && python -m aurascan init
```

Then verify the local setup:

```bash
python -m aurascan doctor
```

AuraScan is not currently published to the AUR or official Arch/CachyOS
repositories. Once you build a local Arch package from `packaging/arch/`, or
publish one later, the intended first-use flow is:

```bash
sudo pacman -U ./aurascan-*.pkg.tar.zst && aurascan init
aurascan doctor
```

Installation does not auto-run the wizard, collect API keys, write user config,
or install local `/etc` hooks as a side effect. Setup starts only when you run
`aurascan init` or `python -m aurascan init`.

## Why AuraScan Is Useful For Arch Users

AUR packages can run build scripts. Maintainer/package takeovers, source URL
changes, dependency tricks, weakened checksums, install hooks, and background
persistence patterns are real risks. Reading every PKGBUILD manually is easy to
forget, especially during routine updates.

AuraScan adds a fast automated safety layer before build or install steps. It
is not a replacement for judgment, but it reduces blind spots and gives risky
package behavior a clear review path.

## Installation

For development:

```bash
python -m pip install -e ".[test]"
```

This installs the `aurascan` and `aurascan-makepkg` console scripts into the
active environment. It does not install pacman hooks and does not run the
wizard.

The Arch packaging skeleton lives under `packaging/arch/`. It is a starting
point for an Arch package that installs `/usr/bin/aurascan`,
`/usr/bin/aurascan-makepkg`, the pacman hook template, and a non-interactive
post-install message that points users to `aurascan init` and `aurascan doctor`.
Review and finalize that package recipe before publishing it.

## What It Checks

The default scan is conservative and fast. It inspects package metadata,
PKGBUILD text, declared local install hooks when available, local history, and
available package archives. It can use deterministic rules, ClamAV when
available, source metadata checks, local history diffing, and structured risk
summaries.

Default scans do not download declared sources, clone upstream repositories,
fetch PGP keys, run GPG, run makepkg, install packages, or execute package code.
The default scan context is `unknown`, which keeps update fast paths disabled.

Deep static source inspection is opt-in: --deep-static is explicit. It safely acquires and inspects declared source
archives without executing package code. In this mode AuraScan may verify
detached signatures in an isolated temporary GPG home. Automatic key lookup is
limited to explicit source acquisition/deep-static flows and can be disabled
with `--no-auto-key-fetch` or `--offline`.

## What It Does Not Protect Against

AuraScan is not a sandbox, VM, or runtime behavior monitor. It does not make
makepkg safe after it starts running package functions. It does not guarantee
malware detection, and it cannot see behavior hidden in files it did not fetch
or inspect.

ClamAV integration is useful when available, but a clean ClamAV scan is not
proof of safety. PGP signatures help confirm source integrity and signer
identity, but a valid signature does not prove that upstream code is safe or
that packaging behavior is harmless.

## Basic Usage

First-run setup:

```bash
aurascan init
aurascan doctor
aurascan doctor --check-ai
python -m aurascan init
python -m aurascan doctor
```

`aurascan init` can configure an AI provider, save the API key in
`~/.config/aurascan/.env`, and optionally install a local pacman hook at
`/etc/pacman.d/hooks/aurascan.hook`. API keys are prompted with hidden input
and the user config file is written with restrictive permissions.

`aurascan init` can also configure upgrade preflight defaults. Upgrade
preflight is enabled by default even without an explicit setting, but the
wizard can record your preferred default helper, AI-review behavior, and config
drift assistant policy:

```bash
aurascan init --enable-upgrade-preflight --upgrade-aur-helper auto --enable-upgrade-ai
aurascan init --enable-config-drift --config-drift-ai-diffs ask
aurascan init --disable-upgrade-preflight
```

Network AI analysis is explicit in wizard-created configs. If you choose
local-only mode, AuraScan writes `AURASCAN_AI_ENABLED=0` and keeps normal scans
local. `aurascan doctor` checks the selected provider, key presence, optional
tools, hook status, and config permissions. It does not contact the provider
unless `--check-ai` is supplied.

When AuraScan is launched by a root pacman hook through `sudo`, it also checks
the invoking user's `~/.config/aurascan/.env` when `SUDO_USER` is available.
For root shells, unattended system updates, or hook contexts without an
invoking user, put system-wide AI settings in `/etc/aurascan/.env`.

Scan a PKGBUILD:

```bash
aurascan --pkgbuild ./PKGBUILD
```

Scan a built package archive:

```bash
aurascan --pkg /var/cache/pacman/pkg/example-1.0-1-x86_64.pkg.tar.zst
```

Emit JSON:

```bash
aurascan --json --pkgbuild ./PKGBUILD
```

Run explicit source acquisition and deep static inspection:

```bash
aurascan --deep-static --pkgbuild ./PKGBUILD
aurascan --deep-static --offline --no-auto-key-fetch --pkgbuild ./PKGBUILD
```

## Upgrade Preflight

`aurascan upgrade` is an optional first-class upgrade front door for Arch and
CachyOS systems. It previews the pending upgrade, checks local breakage risks,
then hands off to pacman or a supported AUR helper when it is reasonable to
continue.

```bash
aurascan upgrade
aurascan upgrade --dry-run
aurascan upgrade --verbose
aurascan upgrade --json
aurascan upgrade --aur-helper shelly
aurascan upgrade --no-ai
aurascan upgrade --no-config-drift
```

The repo-package preview uses pacman, and the final repo-only handoff is:

```bash
sudo pacman -Syu
```

When `paru`, `yay`, or `shelly` is selected or auto-detected, AuraScan also
queries AUR updates and hands off to that helper. `paru` and `yay` use `-Syu`;
Shelly uses `shelly upgrade-all --no-flatpak --no-appimage` so the handoff
matches AuraScan's repo/AUR preflight scope. If no supported helper is
available, AuraScan still warns about installed foreign packages that may need
rebuilds after library, kernel, compiler, Python, Qt, or Electron updates.

Upgrade preflight is not a safety guarantee. It checks for practical pitfalls
such as low `/boot` or root space, kernel/module mismatch risk, CachyOS kernel
movement, initramfs or bootloader-sensitive updates, ignored packages that can
create partial upgrades, replacements/conflicts, AUR rebuild risk, local
foreign-package dependency/conflict metadata, and pending `.pacnew`/`.pacsave`
config drift. A clean preflight means AuraScan did not find these signals;
pacman, hooks, packages, or local configuration can still fail.

If HIGH or CRITICAL preflight risk is found, AuraScan asks for one extra
confirmation before running the package-manager command:

```text
AuraScan found upgrade risks. Continue anyway? [y/N]
```

This is not a hard-blocker bypass model. AuraScan does not force system
maintenance to stop; it gives you a clear checkpoint before continuing. Pacman
or the AUR helper will still show its normal confirmation and may still fail.

AI review is optional and raise-only. When AI is configured and not disabled
with `--no-ai`, AuraScan sends a redacted structured summary of package names,
versions, deterministic findings, and selected local system facts. It does not
send API keys, environment variables, full command output, or file contents.
AI may raise a preflight risk or add an advisory `UPG-AI-RISK`, but it cannot
lower deterministic risk, mark an upgrade safe, or hard-block by itself.

The config keys are `AURASCAN_UPGRADE_PREFLIGHT_ENABLED`,
`AURASCAN_UPGRADE_AUR_HELPER`, and `AURASCAN_UPGRADE_PREFLIGHT_AI`.
Supported helper values are `auto`, `paru`, `yay`, `shelly`, and `none`.
`aurascan upgrade --enable-preflight` can temporarily override a disabled
preflight setting, while `--disable-preflight` disables it for that invocation
and does not run the upgrade command.

## Config Drift Assistant

`aurascan config-drift` finds `.pacnew` and `.pacsave` files, explains what
they mean, prepares safe fixes, and creates backups before every write.

```bash
aurascan config-drift
aurascan config-drift --dry-run
aurascan config-drift --json
aurascan config-drift --yes
aurascan config-drift --ai-diffs
```

`aurascan upgrade` runs the assistant before the package-manager handoff and
again after it exits, unless disabled with `--no-config-drift` or config. The
assistant auto-plans low-risk fixes such as duplicate `.pacnew` files,
missing-target installs, comments-only changes, and mirrorlist-style updates.
Sensitive files such as `pacman.conf`, bootloader/initramfs config, sudo/PAM,
networking, users/groups, SSH, systemd, and security policy are treated with
extra caution.

Before applying any fix, AuraScan backs up the active config and drift file
under `/var/lib/aurascan/config-drift/<run-id>/` with a JSON manifest. `.pacsave`
files are explained but not restored or deleted automatically in v1.

AI diff review is optional and opt-in. Network AI sees config diffs only when
`--ai-diffs` is passed or `AURASCAN_CONFIG_DRIFT_AI_DIFFS=always` is configured.
Diffs are bounded and redacted first, but AuraScan still treats AI as advisory:
AI cannot bypass backups, deterministic file classification, or sensitive-file
confirmation rules.

The config keys are `AURASCAN_CONFIG_DRIFT_ENABLED` and
`AURASCAN_CONFIG_DRIFT_AI_DIFFS`, where AI diff policy is `ask`, `never`, or
`always`.

## makepkg Wrapper

`aurascan-makepkg` is the preferred AUR-helper integration point when the helper
can be configured to use a custom makepkg command.

```bash
aurascan-makepkg --syncdeps
aurascan-makepkg --aurascan-deep-static --syncdeps
aurascan-makepkg --aurascan-json --syncdeps
```

The wrapper scans the current directory's `PKGBUILD` before invoking the real
`makepkg`. AuraScan-only flags use the `--aurascan-*` prefix and are stripped
before makepkg receives its arguments. If AuraScan blocks or requires review,
makepkg is not invoked by default.

The wrapper protects the pre-build phase. It does not sandbox makepkg, install
packages, or make package code safe after makepkg starts running build steps.

## Pacman Hook

The release-safe pacman hook template is `packaging/arch/aurascan.hook`. The
root `aurascan.hook` mirrors that release-safe template. It calls the installed
`/usr/bin/aurascan` executable and does not point at a source checkout, virtual
environment, or developer home directory.

A pacman hook scans already built package archives before the pacman
transaction. This is useful for archive and install-metadata review, but it is
too late to protect against malicious PKGBUILD build-time logic that may have
run during package creation.

The makepkg wrapper and pacman hook are different tools:

- `aurascan-makepkg` scans before makepkg executes package build functions.
- The pacman hook scans built package archives before pacman installs them.

The current hook is conservative and does not provide a verified pacman
transaction context provider for smart update fast paths.

`pip install` does not install pacman hooks. Plainly, pip install does not install pacman hooks. Pacman hooks require root or
package-manager installation. The preferred release path is an Arch package
that installs the hook to `/usr/share/libalpm/hooks/aurascan.hook` and removes
it when the package is uninstalled. Manual installation to
`/etc/pacman.d/hooks/` is possible, but should be done carefully. Do not leave a
hook behind that points to a missing executable; remove the hook or reinstall
AuraScan before continuing pacman transactions.

The hook uses pacman's `NeedsTargets` mode. AuraScan reads target names from
stdin, scans an existing target path when one is provided, or looks for the
latest matching `.pkg.tar.zst` file in `/var/cache/pacman/pkg`. Missing archive
targets are reported as warnings and do not block by themselves. Blocking
findings make AuraScan exit non-zero, which should stop the pacman transaction.
If `clamscan` is unavailable, AuraScan reports that AV scanning was skipped and
continues with the remaining checks. If `/usr/bin/aurascan` is missing, pacman
cannot run the hook command; recover by reinstalling AuraScan or removing the
stale hook from the hook directory.

## Review Acceptance

Some findings require manual review but are not hard blockers. In the makepkg
wrapper, eligible manual-review findings produce a review token. After reading
the findings, the same exact scan can be accepted:

```bash
aurascan-makepkg --aurascan-accept-review arv-... --syncdeps
aurascan-makepkg --aurascan-accept-review arv-... --aurascan-review-reason "reviewed warning" --syncdeps
```

By default, review acceptance is one-time. `--aurascan-remember-review` records
a reusable decision for the same exact scan fingerprint. `--aurascan-review-once`
forces one-time behavior. `--aurascan-review-expire-days N` adds an expiry.

List or revoke decisions:

```bash
aurascan-makepkg --aurascan-list-review-decisions
aurascan-makepkg --aurascan-revoke-review <decision_id>
aurascan-makepkg --aurascan-json --aurascan-list-review-decisions
```

Review acceptance is not clean trust. It does not create a trusted baseline for
smart update fast paths. Hard blockers cannot be accepted through ordinary
review. Confirmed malware signatures, checksum mismatches, invalid signatures,
signer fingerprint mismatches, unsafe archive findings, deterministic CRITICAL
findings, and findings marked as blocking remain stops.

## Update Scan Policies

AuraScan supports update scan policy scaffolding:

- `full`: normal conservative scan path.
- `smart`: may use a fast path only with proven update context, an accepted
  baseline, and trust-diff approval.
- `new-only`: weaker mode that may skip already-installed updates only when
  update context is proven or explicitly user-asserted with opt-in.

`new-only` is weaker protection. Plainly, new-only is weaker protection because malicious behavior can be introduced in
an update. A skipped update does not become a trusted baseline.

"No new dependencies" is not enough to skip a scan. Package name, dependency
stability, AUR metadata, and version strings alone are also not proof that a
scan is a safe update.

`--scan-context auto` uses a local package database provider. It reads local
pacman DB metadata without root, package installation, makepkg, package-code
execution, or network access. If identity, installed state, candidate version,
version comparison, or split-package mapping is ambiguous, AuraScan falls back
to normal conservative behavior.

Manual `--scan-context update` is user-asserted, not provider-verified. It can
participate in smart or new-only decisions only with
`--allow-user-asserted-update-context`, and reports label it as user asserted.

## Privacy And External Tools

Default scans are local unless network AI analysis has been explicitly enabled
or a legacy `AURASCAN_AI_KEY` environment variable is present. The first-run
wizard writes an explicit `AURASCAN_AI_ENABLED` value so the user's choice is
clear. When enabled, package AI analysis may send package metadata, PKGBUILD
text, and install-script text to the configured provider. Config drift diff
review has an additional opt-in gate and sends only redacted bounded diffs.

Supported AI provider IDs are `openai`, `anthropic`, `deepseek`, `gemini`, and
`openrouter`. Provider-specific keys use `AURASCAN_OPENAI_API_KEY`,
`AURASCAN_ANTHROPIC_API_KEY`, `AURASCAN_DEEPSEEK_API_KEY`,
`AURASCAN_GEMINI_API_KEY`, or `AURASCAN_OPENROUTER_API_KEY`. Legacy
`AURASCAN_AI_KEY` remains supported for existing setups.

Deep static source acquisition can contact source hosts and, unless disabled,
a configured keyserver for PGP key lookup. The metadata-only tuning helper
fetches only PKGBUILD and `.SRCINFO` text from the AUR and does not download
declared sources.

External tools are optional where appropriate. Missing ClamAV, GPG, makepkg,
pacman, or vercmp should fail gracefully in the paths that can proceed without
them. Some workflows, such as invoking the makepkg wrapper after a successful
scan, require a real makepkg executable.

## False Positives

AuraScan is intentionally cautious. System service files, cron jobs, dynamic
shell evaluation, checksum changes, signature metadata, and install hooks can
all be legitimate. The terminal presenter tries to explain what was checked,
what was not proven, and what action is recommended.

When a finding is unclear, review the evidence. Do not treat a warning as proof
of malicious intent, and do not treat a clean report as proof of safety.

## Tests And Tuning

Run the core validation:

```bash
python -m compileall aurascan tests tools
.venv/bin/python -m pytest -q
.venv/bin/python tools/audit_presenter_coverage.py
.venv/bin/python tools/audit_presenter_coverage.py --strict
.venv/bin/python tools/audit_presenter_coverage.py --strict-medium
```

Run the metadata-only AUR warning tuning helper:

```bash
.venv/bin/python tools/aur_warning_tune.py --package-list-file tools/package_lists/aur-warning-tune-mixed.txt --limit 50
.venv/bin/python tools/aur_warning_tune.py --package-list-file tools/package_lists/aur-warning-tune-mixed.txt --output-markdown tools/reports/aur-warning-tune.md
```

Metadata-only tuning is opt-in. Live AUR tuning is not part of normal pytest.

## License

AuraScan is released under the MIT License. See [LICENSE](LICENSE).

## Threat Model

AuraScan focuses on reducing package-install risk from malicious or suspicious
packaging behavior, unsafe source archives, weakened source integrity,
dangerous static patterns, suspicious update drift, and known malware
signatures when local scanners are available.

It is a review and blocking layer, not a complete endpoint security system.
Use it alongside normal Arch/CachyOS package trust practices, source review,
maintainer reputation checks, and system backups.
