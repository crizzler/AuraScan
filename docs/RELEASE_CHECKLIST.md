# AuraScan Release Checklist

Use this checklist before a first serious release checkpoint or any release
candidate.

## Validation

- `python -m compileall aurascan tests tools` passes.
- `.venv/bin/python -m pytest -q` passes.
- `.venv/bin/python tools/audit_presenter_coverage.py` passes.
- `.venv/bin/python tools/audit_presenter_coverage.py --strict` passes.
- `.venv/bin/python tools/audit_presenter_coverage.py --strict-medium` passes.
- Curated fixture tests pass.
- Deep-static fixture tests pass.
- AUR repository-propagation tests cover canonical endpoint forms, direct and
  configured-remote AUR push binding, incomplete correlations, comments and
  quoted documentation, dry-run pushes, explicitly non-AUR pushes, and the
  arbitrary acquired-source release-tooling negative.
- Declared install-hook tests cover literal and dot-prefixed targets, bounded
  no-follow reads, missing and unreadable files, ambiguous or unsafe
  declarations, every component of the declared relative hook path under the
  package directory, replacement races, cache transitions, fast paths, review
  binding, history, trust diff, and wrapper refusal before makepkg.
- Instruction Guard fixtures and CLI, state, AI, service, notification, tray,
  disable/restore, and packaging contract tests pass.
- Metadata-only warning sample has been reviewed.
- No live fixture requires network during pytest.
- Tests do not run real makepkg.
- Tests do not execute package code.
- Tests do not require root.
- Secret scan has been reviewed before publishing.
- Internal recovery UKIs boot under QEMU/OVMF with Limine, systemd-boot, and
  GRUB fixtures; the release ISO boots with both OVMF and SeaBIOS.
- `packaging/recovery/qemu-smoke.sh` boots the finalized hybrid ISO in SeaBIOS
  and ordinary OVMF UEFI modes after verifying its release checksum.
- `packaging/recovery/qemu-uki-smoke.sh` boots the finalized local UKI under
  OVMF in ordinary and enrolled-key Secure Boot modes.
- Secure Boot recovery is tested with disposable OVMF owner keys, and unsigned
  internal installation is refused when signing cannot be proven.
- Recovery smoke tests cover Ethernet, saved and manual Wi-Fi, offline fallback,
  provider failure, LUKS+Btrfs, ext4/LVM, interrupted pacman, broken initramfs,
  snapshot confirmation, atomic refresh rollback, and removal.
- No generated local artifacts are staged or committed.
- No virtualenv, cache directory, local DB, generated report, keyring, or
  temporary signature/private-key material is committed.
- Instruction Guard tests use injected temporary roots and never scan the real
  home, contact a provider, start a model, invoke live systemd, or require root.

## Safety Gates

- No generic force flag or hard-blocker bypass exists.
- Hard blockers cannot be accepted through ordinary review.
- Confirmed malware signatures, checksum mismatches, invalid signatures, signer
  fingerprint mismatches, unsafe archive findings, deterministic CRITICAL
  findings, and explicitly blocking findings remain stops.
- `aurascan-makepkg` scans before invoking makepkg.
- Manual review acceptance remains scoped to the exact scan.
- Accepted review is not treated as clean trust.
- Accepted review does not create a trusted smart-update baseline.
- Smart fast path requires verified update context, an accepted baseline, and
  trust-diff approval.
- `new-only` remains documented as weaker protection.
- `new-only` skipped updates do not update trusted history.
- Pacman hook behavior remains conservative unless a verified transaction
  provider exists.
- Release pacman hook template has no developer-local paths.
- Release pacman hook template does not pass `--scan-context update`.
- Release pacman hook template does not enable smart fast path.
- Release pacman hook install path is checked.
- The installed wizard recognizes an active packaged hook without creating a
  redundant local override.
- Pacman hook uninstall path is documented.
- Pacman hook failure recovery is documented.
- `aurascan-makepkg` is documented as build-time protection.
- Pacman hook is documented as archive/install-stage protection.
- For v0.9.2, the package-scanner rule version is `1.3.0`; results cached under
  `1.2.0` cannot authorize a package under the new deterministic semantics.
- `SUPPLYCHAIN-AUR-REPO-PROPAGATION-001` remains a CRITICAL, non-reviewable
  blocker limited to deterministic PKGBUILD and declared install-hook control
  text. It requires a canonical AUR Git target, repository mutation or staging,
  and a non-dry-run push bound to that AUR endpoint or configured remote.
- An AUR URL, clone/fetch behavior, explicitly non-AUR push, dot-prefixed
  filename, comment, quoted documentation, or incomplete behavior family does
  not independently establish AUR repository propagation. Arbitrary release
  tooling found only in acquired deep-static source remains negative.
- AUR repository-propagation evidence remains fixed and secret-free. Its
  explanation describes a potential static propagation chain without claiming
  that package code ran, credentials were available, a push succeeded, or an
  account or machine was compromised.
- Every literal local `install=` target, including a dot-prefixed hook, is
  mandatory evidence before any cached or fast-path allow and before makepkg.
  `INSTALL-HOOK-UNINSPECTED-001` remains a HIGH, non-reviewable blocker when the
  declared hook cannot be inspected safely.
- Install-hook resolution rejects missing, unreadable, unsafe, ambiguous, and
  non-regular targets and any symlinked component of the declared relative hook
  path under the package directory. It never sources the PKGBUILD or executes
  the hook.
- The exact captured hook identity, or its bounded failure-state identity,
  participates in cache, history, trust-diff, and review binding. A matching
  failure-state blocker may be cached, but an unresolved or changed hook cannot
  reuse or store an allow decision or review acceptance.
- Instruction Guard recognizes the documented Claude Code, shared `AGENTS.md`,
  and Agent Skill surfaces without traversing symlink directories or executing,
  importing, rendering, or sourcing their contents.
- Instruction Guard discovery, reads, imports, encodings, files, traversal,
  elapsed time, and continuation state are bounded and race-checked.
- All-Markdown mode performs content analysis only and does not create
  integrity-baseline entries for unrelated Markdown files.
- Instruction Guard behavior findings require documented correlations and
  distinguish active constructs from comments, quoted/fenced examples,
  negation, frontmatter, and invalid configuration.
- Content risk and integrity state remain separate; suspicious first-seen files
  alert immediately and clean first-seen files remain unreviewed until explicit
  approval.
- Instruction Guard approvals bind exact content to machine identity and UID;
  corrupt, symlinked, wrongly owned, or permission-weakened private state fails
  closed without being overwritten.
- Instruction Guard alert output and notifications contain no paths, snippets,
  usernames, credentials, or AI text, and acknowledgment never establishes
  trust.
- Disable refuses stale, changed, non-owned, symlinked, shared, settings, hook,
  plugin-manifest, or script targets. Eligible standalone instruction files
  complete exact atomic disable/receipt/restore round trips and restore as
  unreviewed.
- Instruction Guard does not automatically quarantine a file.
- The offline Instruction Guard user service has no network or AI credentials,
  uses a read-only home and private writable state, and exits successfully after
  recording a security finding.
- Instruction Guard AI has a separate opt-in, processes at most one job per
  timer run, receives no more than 12 KiB of redacted evidence, has no tools,
  and accepts only strict bounded JSON.
- Instruction Guard AI cannot lower deterministic severity, trust an integrity
  change, or propose executable commands; disabled, malformed, or timed-out AI
  preserves deterministic findings and disabled AI makes zero calls.
- Incident root collectors are installed disabled, have no network access, and
  perform no AI requests or repairs themselves.
- Weekly incident timer is installed disabled, persistent, randomized, and
  coupled to the wizard's incident-monitor setting.
- Background incident AI has a separate per-user opt-in, runs only in a user
  session, and has no privilege escalation or writable system paths.
- AI-guided incident planning accepts only locally generated opaque probe IDs,
  runs no more than 12 bounded read-only probes, and makes no more than two
  provider requests per incident.
- Background prepared plans remain private, expire after six hours, and refresh
  probes plus root-side preconditions before any confirmed execution.
- Safe Autopilot defaults to `off`, has no network or AI credentials, and
  accepts only stale-lock and verified mirrorlist restoration recipes.
- Background, guarded incident, and Safe Autopilot AI output cannot authorize,
  create, execute, or mark a repair successful.
- Safe Autopilot refuses incomplete/HIGH-risk reports, limits each run to two
  actions, and enforces a 24-hour identical-action cooldown.
- Weekly checkpoint is root-only; public status contains timing and collection
  health only.
- Incident pending markers contain only marker type, scan ID, boot ID, UID
  scope, category severities, resolved categories, coarse repair state, count,
  and repeated state; no evidence, paths, AI text, package/application names,
  or commands.
- Clean weekly scans are silent; only HIGH/CRITICAL or repeated crashes notify.
- The tray exposes one incident-resolution action and clearly distinguishes
  repaired findings from reviewed historical evidence.
- Instruction Guard tray toggles use the asynchronous no-shell transactional
  CLI, serialize mutations, bound combined child output and runtime, retire Qt
  process/timer children, keep notifications secret-free, and disable the
  tray's own Quit action until rollback-sensitive operations finish.
- Incident repair actions are allowlisted and freshly revalidated as root.
- AI-generated commands and fabricated incident evidence/action IDs are
  rejected outside an explicitly granted foreground Repair Agent shell session.
- Fabricated diagnostic probe IDs and provider-supplied targets are rejected.
- Follow-up contexts are private, fingerprinted, redacted before persistence,
  and retained for no more than 30 days or 50 records.
- Follow-up AI accepts only known fact, probe, and action IDs; provider-supplied
  executable fields and unknown IDs are discarded.
- Hardware-aware follow-up runs only in an opted-in foreground AI workflow,
  uses bounded read-only probes, excludes serials/UUIDs/raw SPD data, and does
  not install drivers or firmware.
- Offline incident collectors do not execute foreground hardware commands,
  refresh firmware metadata, or contact the network.
- Transient desktop application units are retained as crash evidence but are
  never prepared as persistent service-restart repairs.
- Follow-up sessions enforce eight-question, twelve-request, and
  12,000-character request bounds.
- Follow-up actions refresh deterministic state, show one separate
  confirmation, and are never authorized by a parent `--yes`.
- JSON, non-interactive, `--yes`, `--no-ai`, hook, root collector, background
  service, and recovery runtime paths do not open follow-up chat.
- Repair Agent defaults to `guarded`; user-shell and root-shell require explicit
  user configuration and an interactive foreground terminal.
- Root-shell also requires a safe root-owned policy, package-managed helper,
  exact typed per-session grant, short-lived PID/start-time/TTY/context-bound
  capability, and a snapshot or exact typed rollback waiver.
- `--yes`, JSON, noninteractive, hook, collector, background, and recovery paths
  cannot start Repair Agent command execution.
- Root executor requests are regular `0600` files owned by the invoking user,
  bounded in size, schema-validated, capability-bound, and limited to 30
  commands per session.
- Root broker environment contains no AI key or provider configuration. User
  and root audits are private, bounded, redacted, and retention-limited.
- Raw terminal output sharing requires a separate exact phrase and remains
  bounded to 32 KiB per command and 128 KiB per session.
- Documentation explicitly states that unrestricted root is user-authorized
  remote code execution and can defeat AuraScan safeguards after execution.
- The warning uses the phrase "user-authorized remote code execution" without
  presenting snapshots, auditing, or process termination as containment.
- Recovery image installation is explicit, staged, fully validated, and atomic;
  package installation never modifies an ESP or bootloader.
- The complete UKI and ISO are scanned to ensure no API key, Wi-Fi profile,
  username, home path, hostname, or incident evidence is embedded.
- Recovery AI uses only separately consented bounded evidence and opaque probe
  or action IDs; session keys are never persisted.
- Snapshot restore and bootloader reinstall retain exact typed confirmations
  that `--yes` cannot bypass.
- USB writing rejects non-removable, mounted, partition, and running/root disks,
  then verifies the written image hash.
- Filesystem repair, partition changes, Secure Boot key enrollment, firmware,
  authentication policy, user-data deletion, arbitrary AI commands, and
  automatic reboot remain prohibited in recovery.

## Defaults

- Default fast scan does not download declared sources.
- Default fast scan does not fetch PGP keys.
- Default fast scan does not run GPG.
- Default scan context is `unknown`.
- `--scan-context auto` is explicit.
- `--deep-static` is explicit.
- Automatic key fetch happens only in explicit source acquisition/deep-static
  flows and can be disabled.
- `--deep-static` overrides smart fast-path source-scan skipping.
- "No new dependencies" is not treated as proof that scanning can be skipped.
- Package installation does not build or enable AuraScan Recovery; the wizard
  offers it only after compatibility checks pass.
- Repair Agent access defaults to `guarded`, approval defaults to
  `each-command`, output sharing defaults to `redacted`, and root policy
  defaults to disabled.
- Instruction Guard monitor and AI timers default to disabled; its default scan
  mode is `agent-surfaces`, while `all-markdown` remains explicit.

## Packaging Metadata

- `pyproject.toml` version is correct for the release.
- GitHub release notes exist under `docs/releases/` for the release.
- `aurascan` console script points to `aurascan.cli:main`.
- `aurascan-makepkg` console script points to `aurascan.makepkg_wrapper:main`.
- Runtime dependencies remain minimal and documented.
- Test dependencies are optional and documented.
- External tools such as ClamAV, GPG, makepkg, pacman, and vercmp are treated as
  optional or workflow-specific where appropriate.
- If a pacman hook is packaged, the installed hook path and `Exec` command are
  checked for the target package format.
- If the AuraScan Updater tray applet is packaged, the desktop file and icon
  are installed without enabling per-user autostart automatically.
- If the incident monitor is packaged, its systemd service and tmpfiles rules
  are installed without enabling or starting the service automatically.
- Instruction Guard offline monitor and separately consented AI service/timer
  are packaged without enabling or starting either. The monitor has
  `PrivateNetwork=yes`, and the assistant processes one queued job per run.
- `libnotify` remains optional; missing `notify-send` does not prevent private
  CLI/tray review state.
- User AI and Safe Autopilot units are packaged without enabling either, and
  package scripts never write the system repair policy.
- Recovery mkosi, systemd, bootloader, tmpfiles, refresh hook, ISO manifest, and
  Archiso profile assets are installed without enabling a boot entry.
- The hybrid ISO is built from a clean committed release candidate with an
  empty self-download digest; the tested ISO digest is then pinned in the final
  host/AUR package before tagging, avoiding a self-referential image hash.
- Package data or package files include the hook template only when intended.
- Root-level development hooks are not accidentally packaged.

## Documentation

- README describes the threat model without overclaiming safety.
- README states that a clean report is not proof of safety.
- README states that a clean ClamAV result is not proof of safety.
- README states that a valid signature is not proof of safety.
- README explains default scan behavior and `--deep-static`.
- README explains source acquisition and PGP verification behavior.
- README explains makepkg wrapper behavior.
- README explains pacman hook limitations.
- README explains pacman hook install and uninstall expectations.
- README explains pacman hook failure behavior.
- README explains review list/revoke/acceptance workflow.
- README explains JSON output.
- README explains `full`, `smart`, and `new-only` update policies.
- README explains why `new-only` is weaker.
- README explains why dependency stability is not enough to skip scans.
- README explains local package DB context proof and `--scan-context auto`.
- README explains privacy expectations.
- README and privacy documentation explain Instruction Guard discovery,
  first-seen/integrity behavior, private state, secret-free alerts, AI consent,
  and confirmed reversible disable/restore limits.
- README states that Instruction Guard is periodic detection, not
  pasted-command/link preflight, privileged fanotify/process interception,
  automatic quarantine, or a boundary against same-UID/root malware.
- README explains incident evidence bounds, redaction, AI opt-in behavior, and
  the repair allowlist boundary.
- README and privacy documentation explain contextual follow-up retention,
  request bounds, AI ID validation, and separate action confirmation.
- README explains false positives and manual review.
- Generated report hygiene is documented.
- MIT license is present.
- README is up to date for the release.
- GitHub repository description and topics are up to date for discovery.
- Announcement/community-post draft is up to date when the release introduces
  user-visible workflow changes.
- `pyproject.toml` metadata is reviewed.
- No developer-local absolute paths remain in release files.

## Distribution And Discovery

- GitHub release is published for the tag.
- Release is marked as the latest release when appropriate.
- Repository topics include Arch-family/AUR/pacman/security discovery terms,
  including Arch Linux, EndeavourOS, Manjaro, and CachyOS where appropriate.
- AUR packaging source URL points at the public GitHub repo before publication.
- AUR publication has a generated `.SRCINFO` and real checksums, or the package
  remains clearly documented as a skeleton.
- External posts link directly to the repo or release and state the developer
  preview limits.

## Generated Reports

- Live tuning reports are ignored or intentionally documented.
- Huge live sample reports are not committed as fixtures.
- Any committed sample report is small, illustrative, and clearly marked as not
  authoritative.
- Live AUR sampling is not part of normal pytest.
