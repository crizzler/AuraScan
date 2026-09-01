# AuraScan Announcement Draft

Use this as a starting point for Arch-family communities, Reddit, Mastodon,
Matrix, or Discord posts. Keep the tone transparent: AuraScan reduces risk, but
it does not prove package safety.

## Short Post

AuraScan is an early developer-preview safety layer for Arch Linux,
EndeavourOS, Manjaro, CachyOS, and AUR workflows.

The v0.10.2 release adds an always-on static provenance check for opaque
binaries and archives observed in the local package directory beside a
PKGBUILD. Presence alone is a MEDIUM, non-hard-blocking,
acceptance-eligible review signal. AuraScan raises that to HIGH when package
text requests copying or installing the exact artifact into the package, and
blocks as CRITICAL only when package text requests invoking or code-loading
the proven artifact, or assigning it SUID/SGID permissions.

The scanner uses bounded no-follow reads and does not invoke Git, extract the
artifact, contact a network, or execute package content. Declared local sources
stay in the normal source-provenance workflow, while ordinary upstream `-bin`
packages with a declared HTTPS archive and fixed checksum are not flagged just
because their acquired payload is binary. The report that motivated this work
explicitly did not accuse the named packages of being malicious; AuraScan also
reports provenance and static use, not a confirmed compromise.

The v0.10.1 release redesigns Agent Instruction Guard reviews around the
question users actually need answered: what was found, on which exact lines,
and why the behavior matters. Suspicious instructions, incomplete scan
coverage, and new or changed files awaiting integrity approval now appear as
separate states instead of sharing an ambiguous LOW-style review list.

Each suspicious correlation pairs its contributing line ranges with their
actual roles, such as retrieval or later execution, followed by a fixed
deterministic explanation. Optional AI reasoning is clearly advisory and
evidence-mapped; it cannot move a line, lower severity, or establish trust.
Clean first-seen files get a concrete compact approval step without being
described as malware.

New deterministic blockers correlate remote downloads with later execution
across bounded variables, pipelines, decoders, install hooks, built-package
control files, and acquired source. They also catch image, document, font, or
media-named files when package logic actually decodes or invokes them as code,
without treating an ordinary bundled asset as malware.

Agent Instruction Guard reviews now show the suspicious behavior, deterministic
line range, and reason behind a finding. The existing tray toggles still control
the deterministic background monitor and separately consented raise-only AI
analysis without exposing paths or secrets in notifications.

Agent Instruction Guard periodically reviews recognized Claude Code,
`AGENTS.md`, and Agent Skill control files without executing them. Suspicious
behavior and unexpected changes remain separate review signals, and the feature
is detection rather than pasted-command interception or same-user containment.

The v0.8 release adds blocking behavior-chain detection for root remote-access
backdoors such as the reported `hyprland-fixes` package. It correlates
privileged Tailscale enrollment or hidden root SSH with persistence,
passwordless sudo/SUID changes, or anti-forensics instead of flagging an
ordinary `tailscaled` service. `aurascan security-audit` also checks bounded
package history and exact reported host artifacts without executing them.

Optional AI can now stay on the same machine through LM Studio or llama.cpp.
These providers are explicitly enabled, restricted to loopback, may be keyless,
and never fall back to a cloud provider.

It can scan PKGBUILDs and package archives, wrap makepkg before build scripts
run, preview risky upgrade conditions with `aurascan upgrade --dry-run`, and
help explain `.pacnew`/`.pacsave` config drift with backups before applying
safe fixes. The new `aurascan incidents --dry-run` command can also inspect
bounded crash evidence and explain likely system or application failures.
An optional weekly local scan can also catch recoverable errors during long
uptime. Separately opted-in logged-in AI can select bounded read-only local
diagnostic probes, then explain and prioritize the independently verified
repair plan. The offline Safe Autopilot still handles only reversible
lock/mirror repairs.

The v0.6 work adds an optional `AuraScan Recovery` boot environment. It starts
offline diagnostics when the installed OS cannot boot, helps connect Ethernet
or WPA2/WPA3 Wi-Fi, and uses separately consented AI only to select opaque local
checks and prioritize independently verified repairs. Internal UEFI recovery is
installed only on request; a hybrid BIOS/UEFI USB image is the fallback.

The new `aurascan upgrade` flow is designed as a native-feeling upgrade front
door: it previews repo and AUR updates, checks kernel/module/initramfs/boot
space/ignored-package/config-drift risks, optionally asks configured AI to
raise risk severity, then hands off to pacman, paru, yay, or Shelly.

After a foreground upgrade, incident, maintenance, or config-drift result, users
can now ask a bounded follow-up question in the same terminal. `aurascan ask
--latest` reopens the newest retained result. AI can select only AuraScan-owned
local probes and verified actions; it cannot create commands, and every action
is refreshed, previewed, and confirmed separately.

Hardware-related questions now gather a fresh, read-only local summary before
AI answers. Supported systems can contribute CPU/GPU/RAM/mainboard/BIOS facts,
temperatures and fan state, driver and microcode versions, current-boot
hardware-error categories, repository update comparisons, and `fwupd` firmware
availability. AuraScan explicitly reports missing coverage and excludes
serials, UUIDs, and raw SPD/firmware data.

An experimental foreground `aurascan agent` keeps guarded behavior by default.
Its compatibility profiles `user-shell` and `root-shell` are policy-gated, not
general shell grants: they accept only allowlisted local diagnostics and
constrained exact `/usr/bin/pacman` repairs, with fresh confirmation for every
model-authored command. Remote, Git/AUR/build, interpreter, decode/eval,
expansion, redirection, and arbitrary-executable paths are rejected before
confirmation. Root mode additionally requires a root-owned policy, a typed
grant for every session, and a snapshot or typed rollback waiver; background
services and Recovery v1 cannot start it.

Repo: https://github.com/crizzler/AuraScan

Try:

```bash
python -m pip install -e ".[test]"
python -m aurascan init
python -m aurascan security-audit
python -m aurascan upgrade --dry-run
python -m aurascan config-drift --dry-run
python -m aurascan incidents --dry-run --no-ai
python -m aurascan instruction-audit --status
python -m aurascan recovery --status
python -m aurascan ask --latest
python -m aurascan agent --latest
```

Important limits: AuraScan is a developer preview. A clean report is not proof
that a package or upgrade is safe. Provider AI is optional and advisory. The
project is looking for testing, packaging feedback, and real-world false
positive reports.

## Longer Post

I am building AuraScan, a security-focused assistant for Arch-family package
workflows.

The original goal was to make AUR package review less easy to skip. AuraScan
looks for risky PKGBUILD patterns, install hooks, unsafe source/archive
behavior, checksum/signature drift, local history changes, and optional ClamAV
or AI signals. It can also be used through `aurascan-makepkg` so the review
happens before makepkg runs package functions.

The v0.10.2 package scanner snapshots opaque ELF, PE, Mach-O, and archive files
present beside a PKGBUILD before cache reuse or source acquisition. It
correlates exact artifact identity with static requests for package staging,
execution, code loading, and SUID/SGID permission changes, and fails closed
when bounded inspection cannot complete. Snapshot identity is also bound into
history, trust, review, and the final makepkg-wrapper revalidation, so changing
only the opaque file cannot reuse an earlier clear result. This is a filesystem
observation, not proof that an artifact was committed to the AUR, installed,
executed, or malicious.

The v0.10.1 review update separates suspicious instructions, incomplete scan
coverage, and integrity approval; adds exact per-line behavior roles and fixed
reasons; and keeps optional AI explanations bounded, evidence-mapped, and
advisory. Terminal output wraps cleanly without displaying source snippets or
potential secrets, while schema-compatible JSON bypasses terminal wrapping.

The v0.10.0 security update separates AI interpretation from authority. Model
output cannot select network targets, create commands, lower deterministic
risk, establish trust, or authorize a repair. Accepted prose remains untrusted
interpretation, and rejected instructions or destinations become fixed
secret-free explanations.

Remote-stage analysis now follows bounded artifact identity through variables,
pipeline filters, redirections, decoders, copies, and interpreters. Unknown
transformations that feed later execution stop as incomplete inspection rather
than being called clear or malicious. Images and other opaque bytes are never
rendered or sent to a multimodal model.

The earlier AUR-maintainer-worm blocker remains limited to package control text
that combines an AUR Git destination, repository mutation or staging, and a
non-dry-run push bound to that destination. Static evidence does not prove a
push ran, credentials worked, or compromise occurred.

Declared local install hooks now use bounded no-follow reads and exact cache,
history, trust-diff, and review binding. The makepkg wrapper revalidates the
PKGBUILD and hook after scanning and immediately before invoking makepkg.
Agent Instruction Guard also explains suspicious behavior with line ranges and
fixed reasons, while its periodic monitor and raise-only AI assistant remain
independently controllable from the tray's right-click menu.

The v0.8 security update adds exact `hyprland-fixes` source and exposure
intelligence plus generic correlated detection for privileged Tailscale SSH,
alternate-port root SSH, systemd/SUID/sudo persistence, and log or history
erasure. Common legitimate Tailscale state is not an alert by itself. Static
matches show suspicious code or artifacts, not proof that attacker access
succeeded.

The newest work adds upgrade safety helpers:

- `aurascan upgrade --dry-run` previews repo and AUR updates.
- It checks low `/boot` or root space, kernel/module rebuild risk, ignored
  packages, initramfs/bootloader-sensitive updates, replacements/conflicts,
  foreign package risk, and `.pacnew`/`.pacsave` drift.
- It supports pacman-only upgrades plus paru, yay, and Shelly handoff.
- AI review is optional and raise-only. It can add caution, but it cannot mark
  an upgrade safe or suppress deterministic findings.
- LM Studio and llama.cpp can provide explicitly enabled loopback-only AI
  without a placeholder API key; AuraScan does not start or manage the model
  server and never redirects these providers to cloud AI.
- `aurascan config-drift --dry-run` explains config drift and prepares safe
  fixes with backups before applying.
- `aurascan incidents --dry-run` examines bounded journal, coredump, pstore,
  package, and module evidence. Its two-pass AI planner may choose only known
  probe IDs and recommend only verified action IDs; repair commands still come
  exclusively from AuraScan's allowlist.
- The optional root collectors are disabled until the user enables them and
  perform no AI requests or repairs themselves. Background AI is a separate
  per-user opt-in that may prepare a private plan but has no execution authority.
- Safe Autopilot is separately disabled by default, stays offline, and permits
  only deterministic stale pacman-lock or verified mirrorlist restoration.
- Enabling incident monitoring also enables a low-priority weekly current-boot
  scan. Clean runs stay silent; the tray changes state for overdue or
  unreviewed maintenance findings.
- The tray exposes one guided **Resolve System Findings** action. Verified
  AuraScan repairs can be confirmed there; historical findings without a safe
  repair are explained and acknowledged without running AI-generated commands.
- The optional tray applet targets KDE first, should work on common
  tray-capable desktops, and may need AppIndicator/status-notifier support on
  GNOME.
- `aurascan recovery` can build an optional local UKI, add an AuraScan-owned
  Limine/systemd-boot/GRUB entry, or write a verified hybrid recovery ISO to an
  eligible removable whole disk. Package installation never changes the ESP.
- Recovery supports bounded Arch-family target discovery across Btrfs, ext4,
  XFS, LUKS2, LVM2, and mdraid, with offline package/boot diagnostics first.
- Recovery AI has separate consent, never receives executable targets, and
  falls back cleanly when networking or a provider is unavailable. Snapshot
  restore and bootloader reinstall require exact typed confirmations.
- Foreground result screens can open contextual follow-up. Sessions are limited
  to eight questions and twelve provider requests; conversations remain
  ephemeral, while only bounded redacted source contexts are retained.
- The optional foreground Repair Agent defaults to guarded tools. The
  policy-gated user/root compatibility profiles require separate settings,
  reject commands outside a local diagnostic/constrained pacman allowlist, and
  require fresh confirmation for every exact command. They are never available
  to background services, hooks, JSON runs, or Recovery v1.

What I would value most:

- Arch, EndeavourOS, Manjaro, and CachyOS users testing dry-run output.
- Packaging and upgrade feedback for the published AUR package.
- False positive reports from real PKGBUILDs and upgrades.
- Suggestions for making the terminal UX friendlier for non-expert Linux users.

Repo: https://github.com/crizzler/AuraScan

This is not a guarantee layer or a replacement for backups. Incident recovery
does not automate filesystem repair, partition changes, Secure Boot key
enrollment, arbitrary AI commands, or reboots. Bootloader recovery is available
only for a positively detected loader/ESP after a separate typed confirmation.
It is an early attempt to make dangerous package and recovery work
more visible before the user has to become an Arch expert.
