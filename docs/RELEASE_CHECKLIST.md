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
- Metadata-only warning sample has been reviewed.
- No live fixture requires network during pytest.
- Tests do not run real makepkg.
- Tests do not execute package code.
- Tests do not require root.
- Secret scan has been reviewed before publishing.
- No generated local artifacts are staged or committed.
- No virtualenv, cache directory, local DB, generated report, keyring, or
  temporary signature/private-key material is committed.

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
- AI output cannot authorize, create, execute, or mark a repair successful.
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
- Incident repair actions are allowlisted and freshly revalidated as root.
- AI-generated commands and fabricated incident evidence/action IDs are
  rejected.
- Fabricated diagnostic probe IDs and provider-supplied targets are rejected.

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
- User AI and Safe Autopilot units are packaged without enabling either, and
  package scripts never write the system repair policy.
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
- README explains incident evidence bounds, redaction, AI opt-in behavior, and
  the repair allowlist boundary.
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
